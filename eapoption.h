/*
  eapoption.h: basic options
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
#include <cstring>
#include <iostream>

using std::uint8_t;
using std::uint32_t;
using std::string;

enum class eap_mode:uint8_t {Standard=0, DigitalChina=1, };

const string all_modes();
std::ostream& operator<<(std::ostream &os,eap_mode m);


class EAPOption
{
public:
    EAPOption():_ip(0),_mask(0),_gateway(0),_dns(0),_mac{0},_cast{0},_mode(eap_mode::Standard),_dhcp(true){}
    EAPOption(const EAPOption&) = delete;
    EAPOption& operator=(const EAPOption&) = delete;
    virtual ~EAPOption(){}

    //get
    void username(const string &x){ _username=x; }
    void password(const string &x){ _password=x; }
    void nic(const string &x){ _nic=x; }

    void ip(const uint32_t x){ _ip=x; }
    void mask(const uint32_t x){ _mask=x; }
    void gateway(const uint32_t x){ _gateway=x; }
    void dns(const uint32_t x){ _dns=x; }
    void mac(const uint8_t x[6]){ std::memcpy(_mac,x,6); }
    void cast(const uint8_t x[6]){ std::memcpy(_cast,x,6); }

    void mode(eap_mode x){ _mode=x; }
    void dhcp(bool x){ _dhcp=x; }

    //set
    const string& username() const { return _username; }
    const string& password() const { return _password; }
    const string& nic() const { return _nic; }

    const uint32_t ip() const { return _ip; }
    const uint32_t mask() const { return _mask; }
    const uint32_t gateway() const { return _gateway; }
    const uint32_t dns() const { return _dns; }
    const uint8_t* mac() const { return _mac; }
    const uint8_t* cast() const { return _cast; }

    eap_mode mode() const { return _mode; }
    bool dhcp() const { return _dhcp; }

protected:
    string _username;
    string _password;
    string _nic;
    uint32_t _ip;
    uint32_t _mask;
    uint32_t _gateway;
    uint32_t _dns;
    uint8_t _mac[6];
    uint8_t _cast[6];
    eap_mode _mode;
    bool _dhcp;
};

