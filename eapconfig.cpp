/*
  eapconfig.cpp: configure settings
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

#include <fstream>
#include <sstream>
#include <map>

#include <boost/regex.hpp>

#include "eapconfig.h"
#include "eaputility.h"
#include "eapnic.h"

using std::cin;
using std::cout;
using std::endl;

const char *config_file_name="configure.ini";

void init_config(EAPOption *option) throw(eap_runtime_error,eap_logic_error)
{
    int index=0,tempi=0;
    string temps;
    try
    {
        cout<<">>"<<++index<<". choose the mode ("<<all_modes()<<"): ";
        cin>>tempi;
        option->mode(static_cast<eap_mode>(tempi));

        //network configure...
        cout<<">>"<<++index<<". choose the network interface card:"<<endl;
        auto nics=get_nics();
        for(int i=0; i<nics.size(); ++i)
        {
            cout<<"\t("<<i<<")"<<nics[i]._desc<<endl;
        }
        cout<<"\tinput the nic number: ";
        cin>>tempi;
        option->nic(nics[tempi]._name);
        option->mac(nics[tempi]._mac);
        option->ip(nics[tempi]._ip);
        option->mask(nics[tempi]._mask);
        option->gateway(nics[tempi]._gateway);
        option->dns(nics[tempi]._dns);

        cout<<">>"<<++index<<". turn dhcp on? (1=yes, 0=no): ";
        cin>>tempi;
        option->dhcp(static_cast<bool>(tempi));
        if(!option->dhcp())
        {
            cout<<">>"<<++index<<". set the ip address (x.x.x.x): ";
            cin>>temps;
            option->ip(str2net(temps));

            cout<<">>"<<++index<<". set the subnet mask (x.x.x.x): ";
            cin>>temps;
            option->mask(str2net(temps));

            cout<<">>"<<++index<<". set the gateway address (x.x.x.x): ";
            cin>>temps;
            option->gateway(str2net(temps));

            cout<<">>"<<++index<<". set the dns address (x.x.x.x): ";
            cin>>temps;
            option->dns(str2net(temps));
        }

        //client configure...
        cout<<">>"<<++index<<". input the user name: ";
        cin>>temps;
        option->username(temps);

        cout<<">>"<<++index<<". input the password: ";
        cin>>temps;
        option->password(temps);
    }
    catch(eap_runtime_error &e)
    {
        throw;
    }
    catch(std::exception &e)
    {
        throw eap_logic_error(e.what());
    }
}

void read_config(EAPOption *option) throw(eap_logic_error)
{

    std::ifstream ifs(config_file_name);
    if(!ifs.good())
    {
        return;
    }

    std::istreambuf_iterator<char> beg(ifs), end;
    string context(beg, end);
    ifs.close();

    std::map<string,string> kv;
    boost::smatch m;
    boost::regex e(R"(^\s*([a-z]+)\s*=\s*(\S+)\s*$)");
    while(boost::regex_search(context,m,e))
    {
        kv[m[1]]=m[2];
        context=m.suffix().str();
    }
    try
    {
        option->mode(static_cast<eap_mode>(std::atoi(kv.at("mode").data())));
        option->dhcp(static_cast<bool>(atoi(kv.at("dhcp").data())));
        option->username(kv.at("username"));
        option->password(decode_passwd(kv.at("password")));
        option->nic(kv.at("nic"));
        uint8_t x[6]= {0};
        option->ip(str2net(kv.at("ip")));
        option->mask(str2net(kv.at("mask")));
        option->gateway(str2net(kv.at("gateway")));
        option->mac(str2net(kv.at("mac"),x));
        option->cast(str2net(kv.at("cast"),x));
    }
    catch(std::exception &e)
    {
        throw eap_logic_error(e.what());
    }
    return;
}

void save_config(const EAPOption *option)
{
    std::stringstream ss;
    ss<<"# configure file used by ccnt"<<endl;
    ss<<"# Copyright (C) 2014 C.C.<exiledkingcc@gmail.com>"<<endl;
    ss<<"# using # for comments"<<endl;
    ss<<"# using key = value to specify the item"<<endl<<endl;

    ss<<"#client mode: "<<all_modes()<<endl;
    ss<<"mode = "<<static_cast<int>(option->mode())<<endl<<endl;

    ss<<"#dhcp: 1=on, 0=off"<<endl;
    ss<<"dhcp = "<<option->dhcp()<<endl<<endl;

    ss<<"#username"<<endl;
    ss<<"username = "<<option->username()<<endl<<endl;
    ss<<"#password(encoded)"<<endl;
    ss<<"password = "<<encode_passwd(option->password())<<endl<<endl;
    ss<<"#network interface card"<<endl;
    ss<<"nic = "<<option->nic()<<endl<<endl;

    ss<<"#ip address: x.x.x.x"<<endl;
    ss<<"ip = "<<net2str(option->ip())<<endl<<endl;
    ss<<"#subnet mask"<<endl;
    ss<<"mask = "<<net2str(option->mask())<<endl<<endl;
    ss<<"#default gateway"<<endl;
    ss<<"gateway = "<<net2str(option->gateway())<<endl<<endl;
    ss<<"#dns"<<endl;
    ss<<"dns = "<<net2str(option->dns())<<endl<<endl;

    ss<<"#mac address: xx:xx:xx:xx:xx:xx"<<endl;
    ss<<"mac = "<<mac2str(option->mac())<<endl<<endl;
    ss<<"#broadcast address"<<endl;
    ss<<"cast = "<<mac2str(option->cast())<<endl<<endl;

    std::ofstream ofs(config_file_name);
    ofs<<ss.str();
    ofs.close();
}

void show_config(const EAPOption *option)
{
    cout<<">>**Configure**"<<endl;
    cout<<">>eap_mode: "<<option->mode()<<endl;
    cout<<">>dhcp: "<<(option->dhcp()?"on":"off")<<endl;

    cout<<">>username: "<<option->username()<<endl;
    //cout<<">>password(encoded): "<<encode_passwd(option->password())<<endl;
    //cout<<">>network interface card name: "<<option->nic()<<endl;

    cout<<">>ip: "<<net2str(option->ip())<<endl;
    cout<<">>mask: "<<net2str(option->mask())<<endl;
    cout<<">>gateway: "<<net2str(option->gateway())<<endl;
    cout<<">>dns: "<<net2str(option->dns())<<endl;

    cout<<">>mac address: "<<mac2str(option->mac())<<endl;
    cout<<">>broadcast address "<<mac2str(option->cast())<<endl;
    cout<<">>########################"<<endl;
}
