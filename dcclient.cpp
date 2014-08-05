/*
  dcclient.cpp: implementation for "Digital China" client
  Copyright (C) 2014 Cheng Chang<exiledkingcc@gmail.com>

  This file is part of ccnt.

  ccnt is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  ccnt is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ccnt.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <cstring>
#include <iostream>
#include "md5.h"
#include "dcclient.h"

using std::memcpy;
using std::memcmp;

DCClient::DCClient(const string& n, const string& p, pcap_t* d, dc_tailer& t)
	:EAPClient(n,p,d),tailer(t)
{
    //alloc packet memory
	start_length=sizeof(ether_header)+sizeof(eapol_header);
	logoff_length=sizeof(ether_header)+sizeof(eapol_header);
	response_length[0]=sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header)+global::MD5_VAL_LEN+sizeof(dc_tailer);
	response_length[1]=sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header)+username.length()+sizeof(dc_tailer);
	response_length[2]=sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header)+sizeof(md5_header)+/* global::MD5_EXT_LEN+ */sizeof(dc_tailer);
	/*there are zero padding (length:MD5_EXT_LEN) in "Digital China" MD5-CHALLENGE packet,
	  but is ok without the padding. */

	start_packet=new uint8_t[start_length];
	logoff_packet=new uint8_t[logoff_length];
	response_packet[0]=new uint8_t[response_length[0]];//KEEP-ALIVE
	response_packet[1]=new uint8_t[response_length[1]];//IDENTIFY
	response_packet[2]=new uint8_t[response_length[2]];//MD5-CHALLENGE
}

DCClient::~DCClient()
{
	delete[] response_packet[2];
	delete[] response_packet[1];
	delete[] response_packet[0];
	delete[] logoff_packet;
	delete[] start_packet;
	response_packet[2]=nullptr;
	response_packet[1]=nullptr;
	response_packet[0]=nullptr;
	logoff_packet=nullptr;
	start_packet=nullptr;
}

void DCClient::init_packets(uint8_t mac[global::ETH_ADR_LEN])
{
	ether_header h0={{0x01,0x80,0xc2,0x00,0x00,0x03},{mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]},{0x88,0x8e}};
	eapol_header h1={0x01,static_cast<uint8_t>(eapol_type::Start),{0}};
	uint8_t *packet=nullptr;

	//init EAPOL-Start packet
	memcpy(start_packet,&h0,sizeof(ether_header));
	memcpy(start_packet+sizeof(ether_header),&h1,sizeof(eapol_header));
	//init EAPOL-Logoff packet
	memcpy(logoff_packet,start_packet,start_length);
	reinterpret_cast<eapol_header*>(logoff_packet+sizeof(ether_header))->type=static_cast<uint8_t>(eapol_type::Logoff);

	//init EAPOL-Response-Identify packet, response_packet[1]
	packet=response_packet[1];
	memcpy(packet,start_packet,start_length);
	packet+=sizeof(ether_header);
	reinterpret_cast<eapol_header*>(packet)->ver=1;
	reinterpret_cast<eapol_header*>(packet)->type=static_cast<uint8_t>(eapol_type::Packet);
	_assign2_(reinterpret_cast<eapol_header*>(packet)->len,sizeof(eap_header)+username.length()+sizeof(dc_tailer));
    packet+=sizeof(eapol_header);
    reinterpret_cast<eap_header*>(packet)->id=1;
    reinterpret_cast<eap_header*>(packet)->code=static_cast<uint8_t>(eap_code::Response);
    reinterpret_cast<eap_header*>(packet)->type=static_cast<uint8_t>(eap_type::Identify);
    _assign2_(reinterpret_cast<eap_header*>(packet)->len,sizeof(eap_header)+username.length());
    packet+=sizeof(eap_header);
    memcpy(packet,username.data(),username.length());
    memcpy(packet+username.length(),&tailer,sizeof(dc_tailer));

	//init EAPOL-Response-MD5-Challenge frame, response_packet[2]
	packet=response_packet[2];
	memcpy(packet,response_packet[1],sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header));
	packet+=sizeof(ether_header);
	_assign2_(reinterpret_cast<eapol_header*>(packet)->len,sizeof(eap_header)+sizeof(md5_header)+sizeof(dc_tailer));
    packet+=sizeof(eapol_header);
    reinterpret_cast<eap_header*>(packet)->id=2;
    reinterpret_cast<eap_header*>(packet)->type=static_cast<uint8_t>(eap_type::MD5_Challenge);
    _assign2_(reinterpret_cast<eap_header*>(packet)->len,sizeof(eap_header)+sizeof(md5_header));
    packet+=sizeof(eap_header);
    reinterpret_cast<md5_header*>(packet)->len=16;
    memcpy(packet+sizeof(md5_header),&tailer,sizeof(dc_tailer));

	//init EAPOL-Response-Keep_Alive frame, response_packet[0]
	packet=response_packet[0];
	memcpy(packet,response_packet[1],sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header));
	packet+=sizeof(ether_header);
	_assign2_(reinterpret_cast<eapol_header*>(packet)->len,sizeof(eap_header)+global::MD5_VAL_LEN+sizeof(dc_tailer));
    packet+=sizeof(eapol_header);
    reinterpret_cast<eap_header*>(packet)->type=static_cast<uint8_t>(eap_type::Keep_Alive);
    _assign2_(reinterpret_cast<eap_header*>(packet)->len,sizeof(eap_header)+global::MD5_VAL_LEN);
    memcpy(packet+sizeof(eap_header)+global::MD5_VAL_LEN,&tailer,sizeof(dc_tailer));

}

void DCClient::start()
{
	if (pcap_sendpacket(pcap_dev,start_packet,start_length) !=0)
    {
        std::cerr<<"ERROR! Sending EAPOL-Start: "<<pcap_geterr(pcap_dev)<<std::endl;
		return;
    }
}

void DCClient::logoff()
{
	if (pcap_sendpacket(pcap_dev,logoff_packet,logoff_length) !=0)
    {
        std::cerr<<"ERROR! Sending EAPOL-Logoff: "<<pcap_geterr(pcap_dev)<<std::endl;
		return;
    }
}

void DCClient::packet_loop()
{
    struct pcap_pkthdr *header;
    uint8_t *pkt_data;
	int ret=-1;
	while(0<=(ret=pcap_next_ex(pcap_dev,&header,const_cast<const u_char**>(&pkt_data))))
    {
        if(ret==0){ continue; }
        if(!packet_handler(pkt_data))
        {
            logoff();
            break;
        }
    }
}

//md5(id+password+data)
void DCClient::calc_md5_challenge(const uint8_t id,const uint8_t data[global::MD5_VAL_LEN],uint8_t md5[global::MD5_VAL_LEN])
{
    MD5 _md5_;
    _md5_.add(&id,1);
    _md5_.add(password.data(),password.length());
    _md5_.add(data,global::MD5_VAL_LEN);
    md5_str2bytes(_md5_.getHash(),md5);
}

//md5(username+data)
void DCClient::calc_md5_keepalive(const uint8_t data[4],uint8_t md5[global::MD5_VAL_LEN])
{
    MD5 _md5_;
    _md5_.add(username.data(),username.length());
    _md5_.add(data,4);
    md5_str2bytes(_md5_.getHash(),md5);
}

bool DCClient::packet_handler(const uint8_t *pkt_data)
{
    if(memcmp(pkt_data,global::eap_addr,global::ETH_ADR_LEN)==0){ return true; }
    //const eapol_header *h1p=reinterpret_cast<const eapol_header*>(pkt_data+sizeof(ether_header));
    const eap_header *h2p=reinterpret_cast<const eap_header*>(pkt_data+sizeof(ether_header)+sizeof(eapol_header));
    const eap_code pkt_code=static_cast<eap_code>(h2p->code);
    const int header_offset=sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header);
    switch(pkt_code)
    {
        case eap_code::Success:
            {
                //there are some magic numbers...
                const char *str=reinterpret_cast<const char*>(pkt_data+0x120);
                std::cerr<<"Success:"<<string(str+2,*(str+1)-2)<<std::endl;
            }break;
        case eap_code::Failure:
            {
                //there are some magic numbers...
                const char *str=reinterpret_cast<const char*>(pkt_data+header_offset+3+16);
                if(0x4f==str[0]&&0x06==str[1]&&0x04==str[2]&&0x02==str[3])
                {
                    str+=8+16;
                }
                std::cerr<<"Failure:"<<string(str+2,*(str+1)-2)<<std::endl;
                return false;
            }break;
        case eap_code::Request:
            {
                std::cerr<<"Response ";
                eap_type pkt_type=static_cast<eap_type>(h2p->type);
                switch(pkt_type)
                {
                    case eap_type::Identify://send response_packet[1]
                        {
                            std::cerr<<"Identify\n";
                            reinterpret_cast<eap_header*>(response_packet[1]+sizeof(ether_header)+sizeof(eapol_header))->id=h2p->id;
                            pcap_sendpacket(pcap_dev,response_packet[1],response_length[1]);
                        }break;
                    case eap_type::MD5_Challenge://send response_packet[2]
                        {
                            std::cerr<<"MD5_Challenge\n";
                            reinterpret_cast<eap_header*>(response_packet[2]+sizeof(ether_header)+sizeof(eapol_header))->id=h2p->id;
                            md5_header *h3p=reinterpret_cast<md5_header*>(response_packet[2]+sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header));
                            calc_md5_challenge(h2p->id,pkt_data+header_offset+1,h3p->val);
                            pcap_sendpacket(pcap_dev,response_packet[2],response_length[2]);
                        }break;
                    case eap_type::Keep_Alive://send response_packet[0]
                        {
                            std::cerr<<"Keep_Alive\n";
                            reinterpret_cast<eap_header*>(response_packet[0]+sizeof(ether_header)+sizeof(eapol_header))->id=h2p->id;
                            uint8_t *md5p=response_packet[0]+sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header);
                            calc_md5_keepalive(pkt_data+header_offset,md5p);
                            pcap_sendpacket(pcap_dev,response_packet[0],response_length[0]);
                        }break;
                    default:break;
                }
            }break;
        default:break;
    }
    return true;
}
