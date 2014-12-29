/*
  port_win32.cpp: win32 related implements
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

#ifndef WIN32  //WIN32 implementations blow
#error "only for win32 implements"
#endif // WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#elif !(_WIN32_WINNT >= 0x0600)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <cstring>
using std::memcpy;

#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#include "eapnic.h"

const std::vector<nic> get_nics() throw(eap_runtime_error)
{
    /** using windows api GetAdaptersAddresses, see
      http://msdn.microsoft.com/en-us/library/windows/desktop/aa365915%28v=vs.85%29.aspx */

    std::vector<nic> all_nics;
    char *addr_buf=new char[0x10000];
    PIP_ADAPTER_ADDRESSES p_adp_addrs=nullptr;
    ULONG buflen=0;
    int ret=0,iter=0;
    do
    {
        p_adp_addrs=reinterpret_cast<PIP_ADAPTER_ADDRESSES>(addr_buf);
        ret=GetAdaptersAddresses(AF_INET,GAA_FLAG_INCLUDE_GATEWAYS,nullptr,p_adp_addrs,&buflen);
    }
    while((ret!=NO_ERROR) && (iter++<4));
    if(ret!=NO_ERROR)
    {
        delete[] addr_buf;
        throw eap_runtime_error("GetAdaptersAddresses failed");
    }

    try
    {
        for(auto p=p_adp_addrs; p!=nullptr; p=p->Next)
        {
            //if(p->IfType!=IF_TYPE_ETHERNET_CSMACD){ continue; }
            const wchar_t *src=p->Description;
            int len=wcslen(src)*4+1;
            char *desc=new char[len];
            memset(desc,0,len);
            mbstate_t ps;
            wcsrtombs(desc,&src,len,&ps);

            nic x(p->AdapterName,desc);
            std::memcpy(x._mac,p->PhysicalAddress,6);
            delete[] desc;

            for(auto pp=p->FirstUnicastAddress; pp!=nullptr; pp=pp->Next)
            {
                if(pp->Address.lpSockaddr->sa_family == AF_INET)
                {
                    x._ip=reinterpret_cast<sockaddr_in*>(pp->Address.lpSockaddr)->sin_addr.s_addr;
                    union{ uint32_t x_; uint8_t y_[4]; } _u;
                    _u.x_=(~0)<<(32-pp->OnLinkPrefixLength);
                    x._mask=(_u.y_[0]<<24)|(_u.y_[1]<<16)|(_u.y_[2]<<8)|(_u.y_[3]);
                    break;
                }
            }
            for(auto pp=p->FirstGatewayAddress; pp!=nullptr; pp=pp->Next)
            {
                if(pp->Address.lpSockaddr->sa_family == AF_INET)
                {
                    x._gateway=reinterpret_cast<sockaddr_in*>(pp->Address.lpSockaddr)->sin_addr.s_addr;
                    break;
                }
            }
            for(auto pp=p->FirstDnsServerAddress; pp!=nullptr; pp=pp->Next)
            {
                if(pp->Address.lpSockaddr->sa_family == AF_INET)
                {
                    x._dns=reinterpret_cast<sockaddr_in*>(pp->Address.lpSockaddr)->sin_addr.s_addr;
                    break;
                }
            }
            x._dhcp=p->Flags&IP_ADAPTER_DHCP_ENABLED;

            all_nics.push_back(x);
        }
    }
    catch(std::exception &e)
    {
        delete[] addr_buf;
        throw eap_runtime_error(e.what());
    }
    delete[] addr_buf;
    return all_nics;
}
