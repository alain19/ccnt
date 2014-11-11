/*
  eapclient.h: eap protocol client prototype
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

#pragma once

#include "eapbase.h"
#include "eaperror.h"
#include "eapoption.h"
#include <pcap.h>

class EAPClient
{
public:
	EAPClient(EAPOption *opt,pcap_t *pdev);
	virtual ~EAPClient();

	EAPClient(const EAPClient&) = delete;
	EAPClient& operator=(const EAPClient&) = delete;

    virtual void prepare(){}
	virtual void start() throw(eap_runtime_error);
	virtual void logoff() throw(eap_runtime_error);
	virtual void packet_loop() throw(eap_error);

protected:
    virtual void packet_handler(const uint8_t*){};

protected:
	EAPOption *_option;
	pcap_t *_pcapdev;
	uint8_t *_start_packet;
	uint8_t *_logoff_packet;
	uint8_t *_response_packet[3];
	int _start_length;
	int _logoff_length;
	int _response_length[3];
};

