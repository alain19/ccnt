/*
  eapclient.h: eap protocol client prototype, no implementation
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

#pragma once

#include <string>
#include <cstdint>
#include "eappacket.h"

using std::string;
using std::uint8_t;

class EAPClient
{
public:
	EAPClient(const string& n,const string& p,pcap_t *d)
		:username(n),password(p),pcap_dev(d),start_packet(nullptr),
		logoff_packet(nullptr),response_packet{nullptr,nullptr,nullptr}{}
	virtual ~EAPClient(){};

	virtual void start(){}
	virtual void logoff(){}
	virtual void packet_loop()=0;

protected:
	string username;
	string password;
	pcap_t *pcap_dev;
	uint8_t *start_packet;
	uint8_t *logoff_packet;
	uint8_t *response_packet[3];
	int start_length;
	int logoff_length;
	int response_length[3];
};

