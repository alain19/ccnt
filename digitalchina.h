/*
  digitalchina.h: "Digital China" client definition
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

#include "eapclient.h"

struct dc_tailer
{
	uint8_t _dhcp;
	uint8_t _ip[4];
	uint8_t _mask[4];
	uint8_t _gateway[4];
	uint8_t _dns[4];
	uint8_t _usr_md5[eap::MD5_VAL_LEN];
	char _client_ver[13];

	dc_tailer():_dhcp(1),_ip{0},_mask{0},_gateway{0},_dns{0},_client_ver{'3','.','5','.','1','0','.','0','4','1','4','f','k'}{}
};

class DCClient: public EAPClient
{
public:
	DCClient(EAPOption *opt,pcap_t *pdev):EAPClient(opt,pdev),_tailer(){}
	virtual ~DCClient(){}

	DCClient(const EAPClient&) = delete;
	DCClient& operator=(const EAPClient&) = delete;

    void prepare() override;

protected:
    void packet_handler(const uint8_t *pkt_data) throw(eap_error) override;

private:
    void calc_md5_challenge(const uint8_t id,const uint8_t data[eap::MD5_VAL_LEN],uint8_t md5[eap::MD5_VAL_LEN]);
    void calc_md5_keepalive(const uint8_t data[4],uint8_t md5[eap::MD5_VAL_LEN]);

private:
    dc_tailer _tailer;
};

