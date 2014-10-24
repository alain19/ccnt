/*
  digitalchina.cpp: implementation for "Digital China" client
  Copyright (C) 2014 C.C.<exiledkingcc@gmail.com>

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
#include "digitalchina.h"
#include "eaputility.h"

using std::memcpy;
using std::memcmp;

void DCClient::prepare()
{
    //initialize the tailer
    _tailer._dhcp=_option->dhcp()?1:0;
    _l2b_(_option->ip(),_tailer._mask);
    _l2b_(_option->mask(),_tailer._gateway);
    _l2b_(_option->gateway(),_tailer._dns);
    _l2b_(_option->dns(),_tailer._ip);
    do_md5(_option->username().data(),_option->username().length(),_tailer._usr_md5);

    // allocate packet memory
	_start_length=sizeof(ether_header)+sizeof(eapol_header);
	_logoff_length=sizeof(ether_header)+sizeof(eapol_header);
	_response_length[0]=sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header)+eap::MD5_VAL_LEN+sizeof(dc_tailer);
	_response_length[1]=sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header)+_option->username().length()+sizeof(dc_tailer);
	_response_length[2]=sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header)+sizeof(md5_header)+/* eap::MD5_EXT_LEN +*/ sizeof(dc_tailer);
	/*there are zero padding (length:MD5_EXT_LEN) in "Digital China" MD5-CHALLENGE packet, but is ok without the padding. */

	_start_packet=new uint8_t[_start_length];
	_logoff_packet=new uint8_t[_logoff_length];
	_response_packet[0]=new uint8_t[_response_length[0]];//KEEP-ALIVE
	_response_packet[1]=new uint8_t[_response_length[1]];//IDENTIFY
	_response_packet[2]=new uint8_t[_response_length[2]];//MD5-CHALLENGE

    // initialize packets
    ether_header h0={{},{},{0x88,0x8e}};
    memcpy(h0.dst,eap::eap_multicast,6);
    memcpy(h0.src,_option->mac(),6);
	eapol_header h1={0x01,static_cast<uint8_t>(eapol_type::Start),{0}};
	uint8_t *packet=nullptr;

	// initialize EAPOL-Start packet
	memcpy(_start_packet,&h0,sizeof(ether_header));
	memcpy(_start_packet+sizeof(ether_header),&h1,sizeof(eapol_header));
	//initialize EAPOL-Logoff packet
	memcpy(_logoff_packet,_start_packet,_start_length);
	reinterpret_cast<eapol_header*>(_logoff_packet+sizeof(ether_header))->type=static_cast<uint8_t>(eapol_type::Logoff);

	//initialize EAPOL-Response-Identify packet, _response_packet[1]
	packet=_response_packet[1];
	memcpy(packet,_start_packet,_start_length);
	packet+=sizeof(ether_header);
	reinterpret_cast<eapol_header*>(packet)->ver=1;
	reinterpret_cast<eapol_header*>(packet)->type=static_cast<uint8_t>(eapol_type::Packet);
	_assign2_(reinterpret_cast<eapol_header*>(packet)->len,sizeof(eap_header)+_option->username().length()+sizeof(dc_tailer));
    packet+=sizeof(eapol_header);
    reinterpret_cast<eap_header*>(packet)->id=1;
    reinterpret_cast<eap_header*>(packet)->code=static_cast<uint8_t>(eap_code::Response);
    reinterpret_cast<eap_header*>(packet)->type=static_cast<uint8_t>(eap_type::Identify);
    _assign2_(reinterpret_cast<eap_header*>(packet)->len,sizeof(eap_header)+_option->username().length());
    packet+=sizeof(eap_header);
    memcpy(packet,_option->username().data(),_option->username().length());
    memcpy(packet+_option->username().length(),&_tailer,sizeof(dc_tailer));

	//initialize EAPOL-Response-MD5-Challenge frame, _response_packet[2]
	packet=_response_packet[2];
	memcpy(packet,_response_packet[1],sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header));
	packet+=sizeof(ether_header);
	_assign2_(reinterpret_cast<eapol_header*>(packet)->len,sizeof(eap_header)+sizeof(md5_header)+sizeof(dc_tailer));
    packet+=sizeof(eapol_header);
    reinterpret_cast<eap_header*>(packet)->id=2;
    reinterpret_cast<eap_header*>(packet)->type=static_cast<uint8_t>(eap_type::MD5_Challenge);
    _assign2_(reinterpret_cast<eap_header*>(packet)->len,sizeof(eap_header)+sizeof(md5_header));
    packet+=sizeof(eap_header);
    reinterpret_cast<md5_header*>(packet)->len=16;
    memcpy(packet+sizeof(md5_header),&_tailer,sizeof(dc_tailer));

	//initialize EAPOL-Response-Keep_Alive frame, _response_packet[0]
	packet=_response_packet[0];
	memcpy(packet,_response_packet[1],sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header));
	packet+=sizeof(ether_header);
	_assign2_(reinterpret_cast<eapol_header*>(packet)->len,sizeof(eap_header)+eap::MD5_VAL_LEN+sizeof(dc_tailer));
    packet+=sizeof(eapol_header);
    reinterpret_cast<eap_header*>(packet)->type=static_cast<uint8_t>(eap_type::Keep_Alive);
    _assign2_(reinterpret_cast<eap_header*>(packet)->len,sizeof(eap_header)+eap::MD5_VAL_LEN);
    memcpy(packet+sizeof(eap_header)+eap::MD5_VAL_LEN,&_tailer,sizeof(dc_tailer));

}

//md5(id+password+data)
void DCClient::calc_md5_challenge(const uint8_t id,const uint8_t data[eap::MD5_VAL_LEN],uint8_t md5[eap::MD5_VAL_LEN])
{
    int num=1+_option->password().length()+eap::MD5_VAL_LEN;
    uint8_t *buff=new uint8_t[num];
    buff[0]=id;
    memcpy(buff+1,_option->password().data(),_option->password().length());
    memcpy(buff+1+_option->password().length(),data,eap::MD5_VAL_LEN);
    do_md5(buff,num,md5);
    delete[] buff;
}

//md5(username+data)
void DCClient::calc_md5_keepalive(const uint8_t data[4],uint8_t md5[eap::MD5_VAL_LEN])
{
    int num=_option->username().length()+4;
    uint8_t *buff=new uint8_t[num];
    memcpy(buff,_option->username().data(),_option->username().length());
    memcpy(buff+_option->username().length(),data,4);
    do_md5(buff,num,md5);
    delete[] buff;
}

void DCClient::packet_handler(const uint8_t *pkt_data) throw(eap_error)
{
    if(memcmp(pkt_data,eap::eap_multicast,6)==0){ return ; }
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
                std::cerr<<"EAPOL-Success:"<<string(str+2,*(str+1)-2)<<std::endl;
            }break;
        case eap_code::Failure:
            {
                //there are some magic numbers...
                const char *str=reinterpret_cast<const char*>(pkt_data+header_offset+3+16);
                if(0x4f==str[0]&&0x06==str[1]&&0x04==str[2]&&0x02==str[3])
                {
                    str+=8+16;
                }
                std::cerr<<"EAPOL-Failure:"<<string(str+2,*(str+1)-2)<<std::endl;
                return ;
            }break;
        case eap_code::Request:
            {
                std::cerr<<"EAPOL-Response: id "<<h2p->id<<":";
                eap_type pkt_type=static_cast<eap_type>(h2p->type);
                switch(pkt_type)
                {
                    case eap_type::Identify://send _response_packet[1]
                        {
                            std::cerr<<"Identify...\n";
                            reinterpret_cast<eap_header*>(_response_packet[1]+sizeof(ether_header)+sizeof(eapol_header))->id=h2p->id;
                            pcap_sendpacket(_pcapdev,_response_packet[1],_response_length[1]);
                        }break;
                    case eap_type::MD5_Challenge://send _response_packet[2]
                        {
                            std::cerr<<"MD5_Challenge...\n";
                            reinterpret_cast<eap_header*>(_response_packet[2]+sizeof(ether_header)+sizeof(eapol_header))->id=h2p->id;
                            md5_header *h3p=reinterpret_cast<md5_header*>(_response_packet[2]+sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header));
                            calc_md5_challenge(h2p->id,pkt_data+header_offset+1,h3p->val);
                            pcap_sendpacket(_pcapdev,_response_packet[2],_response_length[2]);
                        }break;
                    case eap_type::Keep_Alive://send _response_packet[0]
                        {
                            std::cerr<<"Keep_Alive...\n";
                            reinterpret_cast<eap_header*>(_response_packet[0]+sizeof(ether_header)+sizeof(eapol_header))->id=h2p->id;
                            uint8_t *md5p=_response_packet[0]+sizeof(ether_header)+sizeof(eapol_header)+sizeof(eap_header);
                            calc_md5_keepalive(pkt_data+header_offset,md5p);
                            pcap_sendpacket(_pcapdev,_response_packet[0],_response_length[0]);
                        }break;
                    default:break;
                }
            }break;
        default:break;
    }
    return ;
}
