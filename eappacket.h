/*
  eappacket.h: definitions of eap packet head and common operations
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

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifdef WIN32
    #include "wpcap/include/pcap.h"
    #include <iphlpapi.h> //should under pcap.h, which contains winsock2.h
#else //LINUX(UNIX)
    #include <pcap.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <netinet/in.h>
#endif

using std::uint8_t;
using std::string;
using std::vector;

#define _assign2_(a,b) do{(a)[1]=(b)&0xff;(a)[0]=((b)&0xff00)>>8;}while(0)
#define _assign4_(a,b) do{(a)[3]=(b)&0xff;(a)[2]=((b)&0xff00)>>8;(a)[1]=((b)&0xff0000)>>16;(a)[0]=((b)&0xff000000)>>24;}while(0)

namespace global
{
    const int ETH_ADR_LEN=6;
    const int ETH_PKT_LEN=0x10000/*=65536*/;
    const int MD5_VAL_LEN=16;
    const int MD5_EXT_LEN=0x80;
    const int DC_VER_LEN=13;
    const char CLIENT_VER[]="3.5.10.0414fk";
    const uint8_t eap_addr[ETH_ADR_LEN]={0x01,0x80,0xc2,0x00,0x00,0x03};
};

enum class eapol_type:uint8_t {Packet=0, Start=1, Logoff=2, };
enum class eap_code:uint8_t {Request=1, Response=2, Success=3, Failure=4, };
enum class eap_type:uint8_t {Identify=1, MD5_Challenge=4, Keep_Alive=250, };

struct ether_header
{
	uint8_t dst[global::ETH_ADR_LEN];
	uint8_t src[global::ETH_ADR_LEN];
	uint8_t type[2];
};

struct ip_header
{
    uint8_t ver_hl;
    uint8_t diff_srv;
    uint8_t leng[2];
    uint8_t ident[2];
    uint8_t flags_fo[2];
    uint8_t ttl;
    uint8_t proto;
    uint8_t crc[2];
    uint8_t src[4];
    uint8_t dst[4];
    uint8_t opt_pad[4];
};

struct eapol_header
{
	uint8_t ver/*=0x1*/;
	uint8_t type;
	uint8_t len[2];
};

struct eap_header
{
	uint8_t code;
	uint8_t id;
	uint8_t len[2];
	uint8_t type;
};

struct md5_header
{
	uint8_t len/*=16*/;
	uint8_t val[global::MD5_VAL_LEN];
};

struct dc_tailer
{
	uint8_t dhcp;
	uint8_t ip[4];
	uint8_t mask[4];
	uint8_t gateway[4];
	uint8_t dns[4];
	uint8_t usr_md5[global::MD5_VAL_LEN];
	char client_ver[global::DC_VER_LEN];
};

struct device_info
{
    string name;
    string desc;
    uint8_t mac[global::ETH_ADR_LEN];
    device_info(const char *x,const char *y,const uint8_t *m):name(x),desc(y)
    {
        std::memcpy(mac,m,global::ETH_ADR_LEN);
    }
};

vector<device_info> get_all_devices();

bool get_pcap_device(const string& devname, pcap_t **pdev, dc_tailer *dtailer);

void md5_str2bytes(const string& md5str, uint8_t md5bytes[global::MD5_VAL_LEN]);

void print_mac_addr(const uint8_t m[6]);

