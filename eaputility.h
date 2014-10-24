/*
  eaputility.h: utilities
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

#include <cstdint>
#include <string>
using std::uint8_t;
using std::string;

#include <pcap.h>
#include "md5.h"
#include "eaperror.h"

const string net2str(const uint32_t net);
const string net2str(const uint8_t net[4]);
const string mac2str(const uint8_t mac[6]);

const uint32_t str2net(const string &str);
const uint8_t* str2net(const string &str,uint8_t net[4]);
const uint8_t* str2mac(const string &str,uint8_t mac[6]);

const string encode_passwd(const string &text);
const string decode_passwd(const string &code);

void do_md5(const void* data, size_t num, uint8_t md5bytes[]);

void get_pcap_device(const string& devname, pcap_t **pdev) throw(eap_runtime_error);

