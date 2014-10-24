/*
  eaptest.cpp: tests
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

#include "eapbase.h"
#include "eaputility.h"

#define BOOST_TEST_MODULE eaptest
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE( bytes_integer_test )
{
    uint8_t x[4]={0x11,0x22,0x33,0x44};
    uint8_t y[4]={0};
    uint16_t w=0x5566;
    uint32_t l=0x778899aa;

    BOOST_CHECK(_b2w_(x)==0x1122);
    BOOST_CHECK(_b2l_(x)==0x11223344);

    _w2b_(w,y);
    BOOST_CHECK(y[0]==0x66 && y[1]==0x55);

    _l2b_(l,y);
    BOOST_CHECK(y[0]==0xaa && y[1]==0x99 && y[2]==0x88 && y[3]==0x77);
}

BOOST_AUTO_TEST_CASE( net_str_num_exchange_test )
{
    uint8_t x[6]={0x11,0x22,0x33,0x44,0x55,0x66};
    BOOST_CHECK(mac2str(x)=="11:22:33:44:55:66");

    str2mac("90:B1:1C:90:F9:E7",x);
    BOOST_CHECK(x[0]==0x90 && x[1]==0xb1 && x[2]==0x1c && x[3]==0x90 && x[4]==0xf9 && x[5]==0xe7);

    uint8_t y[4]={192,168,0,10};
    BOOST_CHECK(net2str(y)=="192.168.0.10");

    str2net("10.0.168.192",y);
    BOOST_CHECK(y[0]==10 && y[1]==0 && y[2]==168 && y[3]==192);

}
