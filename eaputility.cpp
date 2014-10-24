/*
  eaputility.cpp: utilities
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

#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <pcap.h>
#include "eapbase.h"
#include "eaputility.h"


const string net2str(const uint32_t net)
{
    const uint8_t *p=reinterpret_cast<const uint8_t *>(&net);
    return net2str(p);
}

const string net2str(const uint8_t net[4])
{
    std::stringstream ss;
    ss<<(int)net[0]<<"."<<(int)net[1]<<"."<<(int)net[2]<<"."<<(int)net[3];
    return ss.str();
}

const string mac2str(const uint8_t mac[6])
{
    using std::setw;
    using std::setfill;
    std::stringstream ss;
    ss<<std::hex<<setw(2)<<setfill('0')<<(int)mac[0]<<":"
        <<setw(2)<<setfill('0')<<(int)mac[1]<<":"
        <<setw(2)<<setfill('0')<<(int)mac[2]<<":"
        <<setw(2)<<setfill('0')<<(int)mac[3]<<":"
        <<setw(2)<<setfill('0')<<(int)mac[4]<<":"
        <<setw(2)<<setfill('0')<<(int)mac[5];
    return ss.str();
}


const uint32_t str2net(const string &str)
{
    uint32_t t=0;
    uint8_t *p=reinterpret_cast<uint8_t *>(&t);
    str2net(str,p);
    return t;
}

const uint8_t* str2net(const string &str,uint8_t net[4])
{
    char *p;
    net[0]=std::strtoul(str.data(),&p,10);++p;
    net[1]=std::strtoul(p,&p,10);++p;
    net[2]=std::strtoul(p,&p,10);++p;
    net[3]=std::strtoul(p,&p,10);
    return net;
}

const uint8_t* str2mac(const string &str,uint8_t mac[6])
{
    char *p;
    mac[0]=std::strtoul(str.data(),&p,16);++p;
    mac[1]=std::strtoul(p,&p,16);++p;
    mac[2]=std::strtoul(p,&p,16);++p;
    mac[3]=std::strtoul(p,&p,16);++p;
    mac[4]=std::strtoul(p,&p,16);++p;
    mac[5]=std::strtoul(p,&p,16);
    return mac;
}


const string encode_passwd(const string &text)
{
    static const char *base=R"(!"#$%&'()*+,-./0)";//16bytes
    const int n=text.size();
    char *buff=new char[n<<1];
    std::srand(1);
    for(int i=0;i<n;++i)
    {
        int j=i<<1;
        uint8_t x=static_cast<uint8_t>(text[i])^(std::rand()&0xff);
        buff[j]=base[x>>4];
        buff[j+1]=base[x&0xf];
    }
    string code(buff,buff+(n<<1));
    delete[] buff;
    return code;
}

const string decode_passwd(const string &code)
{
    const int n=code.size()>>1;
    char *buff=new char[n];
    std::srand(1);
    for(int i=0;i<n;++i)
    {
        int j=i<<1;
        uint8_t x=(static_cast<uint8_t>(code[j]-'!')<<4)|static_cast<uint8_t>(code[j+1]-'!');
        buff[i]=x^std::rand();
    }
    string text(buff,buff+n);
    delete[] buff;
    return text;
}

void do_md5(const void* data, size_t num, uint8_t md5bytes[])
{
    MD5 _md5_;
    const string md5str=_md5_(data,num);
    for(int i=0;i<eap::MD5_VAL_LEN;++i)
    {
        int j=i<<1;
        uint8_t x=md5str[j]>='a'?md5str[j]-'a'+10:md5str[j]-'0';
        uint8_t y=md5str[j+1]>='a'?md5str[j+1]-'a'+10:md5str[j+1]-'0';
        md5bytes[i]=(x<<4)|y;
    }
}


void get_pcap_device(const string& devname, pcap_t **ppdev) throw(eap_runtime_error)
{
    pcap_if_t *alldevs=nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs,errbuf) == -1)
    {
        pcap_freealldevs(alldevs);
        throw eap_runtime_error("pcap_findalldevs failed");

    }
    for(auto d=alldevs;d!=nullptr;d=d->next)
    {
        string name(d->name);
        if(name.find(devname)!=string::npos)
        {
            if((*ppdev=pcap_open_live(d->name,eap::ETH_PKT_LEN,0,1000,errbuf))==nullptr)
            {
                pcap_freealldevs(alldevs);
                throw eap_runtime_error("pcap_open failed");
            }
            break;
        }
    }
    pcap_freealldevs(alldevs);
    if(*ppdev==nullptr) { throw eap_runtime_error("no pcap device found"); }

    bpf_program fcode;
    if(pcap_compile(*ppdev,&fcode,"ether proto 0x888e",1,0)<0)
    {
        throw eap_runtime_error("pcap_compile failed");
    }else
    {
        if (pcap_setfilter(*ppdev,&fcode)<0)
        {
            throw eap_runtime_error("pcap_setfilter failed");
        }
    }
}
