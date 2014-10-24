/*
  eapnic.h: nic related parts, depends on os
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
#include <vector>

#include "eaperror.h"

using std::uint8_t;
using std::uint32_t;
using std::string;

struct nic
{
    string _name;
    string _desc;
    uint32_t _ip;
    uint32_t _mask;
    uint32_t _gateway;
    uint32_t _dns;
    uint8_t _mac[6];
    bool _dhcp;

    nic(const string n,const string d):_name(n),_desc(d),
        _ip(0),_mask(0),_gateway(0),_dns(0),_mac{0},_dhcp(true){}
};

const std::vector<nic> get_nics() throw(eap_runtime_error);


