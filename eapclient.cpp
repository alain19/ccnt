/*
  eapclient.cpp: implementation for pure eap client
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

#include "eapclient.h"

EAPClient::EAPClient(EAPOption *opt,pcap_t *pdev):_option(opt),_pcapdev(pdev),
            _start_length(0),_logoff_length(0),_response_length{0,0,0},
            _start_packet(nullptr),_logoff_packet(nullptr),_response_packet{nullptr,nullptr,nullptr}
{}

EAPClient::~EAPClient()
{
    pcap_close(_pcapdev);
    delete[] _response_packet[2];
	delete[] _response_packet[1];
	delete[] _response_packet[0];
	delete[] _logoff_packet;
	delete[] _start_packet;
	_start_packet=nullptr;
	_logoff_packet=nullptr;
	_response_packet[0]=nullptr;
	_response_packet[1]=nullptr;
	_response_packet[2]=nullptr;
	_response_packet[3]=nullptr;
}

void EAPClient::start() throw(eap_runtime_error)
{
	if (pcap_sendpacket(_pcapdev,_start_packet,_start_length) !=0)
    {
		throw eap_runtime_error("ERROR when sending EAPOL-Start:pcap_sendpacket");
    }
}

void EAPClient::logoff() throw(eap_runtime_error)
{
	if (pcap_sendpacket(_pcapdev,_logoff_packet,_logoff_length) !=0)
    {
        throw eap_runtime_error("ERROR when sending EAPOL-Logoff:pcap_sendpacket");
    }
}

void EAPClient::packet_loop() throw(eap_error)
{
    struct pcap_pkthdr *header;
    uint8_t *pkt_data;
	int ret=-1;
	while(0<=(ret=pcap_next_ex(_pcapdev,&header,const_cast<const u_char**>(&pkt_data))))
    {
        if(ret==0){ continue; }
        try{
            packet_handler(pkt_data);
        }
        catch(eap_error&){
            throw;
        }
    }
}
