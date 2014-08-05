/*
  dcclient.h: "Digital China" client definition
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

#include "eapclient.h"

class DCClient: public EAPClient
{
public:
	DCClient (const string& n, const string& p, pcap_t* d, dc_tailer& t);
	virtual ~DCClient ();

	void start() override;
	void logoff() override;
	void packet_loop() override;

    void init_packets(uint8_t mac[global::ETH_ADR_LEN]);

private:
    void calc_md5_challenge(const uint8_t id,const uint8_t data[global::MD5_VAL_LEN],uint8_t md5[global::MD5_VAL_LEN]);
    void calc_md5_keepalive(const uint8_t data[4],uint8_t md5[global::MD5_VAL_LEN]);
    bool packet_handler(const uint8_t *pkt_data);

private:
	dc_tailer tailer;
};

