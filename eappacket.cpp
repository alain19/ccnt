/*
  eappacket.cpp: common operations
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

#include <iostream>
#include <iomanip>
#include "eappacket.h"
#include "md5.h"

vector<device_info> get_all_devices()
{
vector<device_info> results;

#ifdef WIN32
	/*using windows api GetAdaptersAddresses, see
	  http://msdn.microsoft.com/en-us/library/windows/desktop/aa365915%28v=vs.85%29.aspx */
    char *addr_buf=new char[global::ETH_PKT_LEN<<1];
    PIP_ADAPTER_ADDRESSES p_adp_addrs=nullptr;
    ULONG buflen=0;
    int ret=0,iter=0;
    do
    {
        p_adp_addrs=reinterpret_cast<PIP_ADAPTER_ADDRESSES>(addr_buf);
        ret=GetAdaptersAddresses(AF_INET,GAA_FLAG_INCLUDE_PREFIX,nullptr,p_adp_addrs,&buflen);
    }
    while((ret!=NO_ERROR) && (iter++<4));
    if(ret!=NO_ERROR)
    {
        delete[] addr_buf;
        return results;
    }
    for(auto p=p_adp_addrs;p;p=p->Next)
    {
        const wchar_t *src=p->Description;
        int len=wcslen(src)*4+1;
        char *des=new char[len];
        memset(des,0,len);
        mbstate_t ps;
        wcsrtombs(des,&src,len,&ps);
        results.push_back(std::move(device_info(p->AdapterName,des,p->PhysicalAddress)));
        delete[] des;
    }
    delete[] addr_buf;

#else //LINUX(UNIX)

    struct ifreq ifr;
    struct ifconf ifc;
    char buf[2048];

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        std::cerr<<"socket error\n";
        return results;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        std::cerr<<"ioctl error\n";
        return results;
    }

    struct ifreq *ifreqs = ifc.ifc_req;
    int n = ifc.ifc_len / sizeof(struct ifreq);
    for(int i=0;i<n;++i)
    {
        strcpy(ifr.ifr_name,ifreqs[i].ifr_name);
        if(ioctl(sock,SIOCGIFFLAGS,&ifr)==0)
        {
            if(! ( ifr.ifr_flags & IFF_LOOPBACK))//don't count loopback
            {
                if(ioctl(sock,SIOCGIFHWADDR,&ifr)==0)
                {
                    results.push_back(std::move(device_info(ifr.ifr_name,ifr.ifr_name,reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data))));
                }
            }
        }
    }

#endif

    return results;
}

bool get_pcap_device(const string& devname, pcap_t **pdev, dc_tailer *dtailer)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs,errbuf) == -1)
    {
        std::cerr<<"*Error in pcap_findalldevs: "<<errbuf<<std::endl;
        return false;
    }
    for(auto d=alldevs;d!=NULL;d=d->next)
    {
        string name(d->name);
        if(name.find(devname)!=string::npos)
        {
            if((*pdev=pcap_open_live(d->name,global::ETH_PKT_LEN,0,1000,errbuf))==NULL)
            {
                std::cerr<<"*Error in pcap_open: "<<errbuf<<std::endl;
                pcap_freealldevs(alldevs);
                return false;
            }
            for(auto p=d->addresses;p;p=p->next)
            {
                sockaddr *sa=p->addr;
                if(AF_INET==sa->sa_family)
                {
                    _assign4_(dtailer->ip,static_cast<uint32_t>(reinterpret_cast<sockaddr_in*>(sa)->sin_addr.s_addr));
                    sa=p->netmask;
                    _assign4_(dtailer->mask,static_cast<uint32_t>(reinterpret_cast<sockaddr_in*>(sa)->sin_addr.s_addr));
                    break;
                }
            }
            break;
        }
    }
    pcap_freealldevs(alldevs);
    struct bpf_program fcode;
    if(pcap_compile(*pdev,&fcode,"ether proto 0x888e",1,0)<0)
    {
        std::cerr<<"*Error in pcap_compile: "<<pcap_geterr(*pdev)<<std::endl;
    }else
    {
        if (pcap_setfilter(*pdev,&fcode)<0)
        {
            std::cerr<<"*Error in pcap_setfilter: "<<pcap_geterr(*pdev)<<std::endl;
        }
    }
    return true;
}

void md5_str2bytes(const string& md5str, uint8_t md5bytes[global::MD5_VAL_LEN])
{
    for(int i=0;i<global::MD5_VAL_LEN;++i)
    {
        int j=i<<1;
        uint8_t x=md5str[j]>='a'?md5str[j]-'a'+10:md5str[j]-'0';
        uint8_t y=md5str[j+1]>='a'?md5str[j+1]-'a'+10:md5str[j+1]-'0';
        md5bytes[i]=(x<<4)|y;
    }
}

void print_mac_addr(const uint8_t m[6])
{
    using std::cout;
    using std::hex;
    using std::setw;
    using std::setfill;
    using std::endl;
    cout<<hex<<setw(2)<<setfill('0')<<(int)m[0]<<":"
        <<setw(2)<<setfill('0')<<(int)m[1]<<":"
        <<setw(2)<<setfill('0')<<(int)m[2]<<":"
        <<setw(2)<<setfill('0')<<(int)m[3]<<":"
        <<setw(2)<<setfill('0')<<(int)m[4]<<":"
        <<setw(2)<<setfill('0')<<(int)m[5]<<endl;
}

