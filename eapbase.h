/*
  eapbase.h: basic elements
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

#define CCNT_VERSION "0.8"

#define _assign2_(d,s) do{(d)[1]=(s)&0xff;(d)[0]=((s)&0xff00)>>8;}while(0)
//#define _assign4_(d,s) do{(d)[3]=(s)&0xff;(d)[2]=((s)&0xff00)>>8;(d)[1]=((s)&0xff0000)>>16;(d)[0]=((s)&0xff000000)>>24;}while(0)

namespace eap
{
    const int ETH_PKT_LEN=0x10000/*=65536*/;
    const int MD5_VAL_LEN=16;
    const int MD5_EXT_LEN=0x80;
    const int EAPOL_TYPE[2]={0x88,0x8e};
    const uint8_t eap_multicast[6]={0x01,0x80,0xc2,0x00,0x00,0x03};
};

enum class eapol_type:uint8_t {Packet=0, Start=1, Logoff=2, };
enum class eap_code:uint8_t {Request=1, Response=2, Success=3, Failure=4, };
enum class eap_type:uint8_t {Identify=1, MD5_Challenge=4, Keep_Alive=250, };

struct ether_header
{
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t type[2];
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
	uint8_t val[eap::MD5_VAL_LEN];
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

inline uint16_t _b2w_(uint8_t b[2]) { return static_cast<uint16_t>(b[1])|(b[0]<<8); }
inline uint32_t _b2l_(uint8_t b[4]) { return static_cast<uint32_t>(b[3])|(b[2]<<8)|(b[1]<<16)|(b[0]<<24); }

inline void _w2b_(uint16_t w,uint8_t b[2]) { b[0]=w; b[1]=w>>8; }
inline void _l2b_(uint32_t l,uint8_t b[4]) { b[0]=l; b[1]=l>>8; b[2]=l>>16; b[3]=l>>24; }
