/*
  main.cpp
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

#include <iostream>
#include <fstream>

#include <boost/program_options.hpp>
#include <signal.h>

#include "eapconfig.h"
#include "eaputility.h"
#include "eapcommon.h"

using namespace std;
namespace po=boost::program_options;

int main(int argc, char *argv[])
{
	if(!enter_running())
	{
		cout<<"ccnt is already running!"<<endl;
		return 0;
	}else
	{
		atexit(leave_running);
		signal(SIGHUP,exit);
    	signal(SIGINT,exit);
    	signal(SIGTERM,exit);
	}

    po::options_description general_po("General options");
    general_po.add_options()
        ("help,h","produce a help message")
        ("version,v","output the version")
        ("init","initialize the configure, save int the configure file, ignore other arguments")
        ("once","apply the configure only once, do not save in the configure file")
        ;

    po::options_description client_po("Client options");
    client_po.add_options()
        ("mode,m",po::value<int>(),"client mode, 0 for Standard(default), 1 for DigitalChina")
        ("user,u",po::value<string>(),"user name")
        ("passwd,p",po::value<string>(),"password")
        ("nic",po::value<string>(),"network interface card name")
        ;

    po::options_description net_po("Network options");
    net_po.add_options()
        ("dhcp","turn dhcp on")
        ("ip",po::value<string>(),"ip address, using x.x.x.x dec format, not needed if dhcp is on, the same below")
        ("mask",po::value<string>(),"ip mask, x.x.x.x")
        ("gateway",po::value<string>(),"gateway address, x.x.x.x")
        ("dns",po::value<string>(),"dns address, x.x.x.x")
        ("mac",po::value<string>(),"mac address, using x:x:x:x:x:x hex format, not needed if using local nic address")
        ("cast",po::value<string>(),"broadcast address, x:x:x:x:x:x")
        ;

    po::options_description all;
    all.add(general_po).add(client_po).add(net_po);
    po::variables_map vm;
    try{
        po::store(po::parse_command_line(argc,argv,all), vm);
    }catch(po::unknown_option &e)
    {
        cout<<e.what()<<endl<<"please try --help..."<<endl;
        exit(0);
    }

    if(vm.count("help")) { cout<<"Usage: ccnt [options] args\n"<<all<<"\nBug report: cc<exiledkingcc@gmail.com>"<<endl; exit(0); }
    if(vm.count("version")) { cout<<"ccnt version "<<CCNT_VERSION<<endl<<"Copyright (C) 2014 cc<exiledkingcc@gmail.com>"<<endl; exit(0); }

    EAPOption eap_option;
    eap_option.cast(eap::eap_multicast);
    if(vm.count("init"))
    {
        try{
            init_config(&eap_option);
        }catch(eap_error &e)
        {
            cout<<e.what()<<endl<<"please check the input and try again..."<<endl;
            exit(0);
        }
        save_config(&eap_option);
    }
    else
    {
        try{
            read_config(&eap_option);
        }catch(eap_error &e)
        {
            cout<<e.what()<<endl<<"please make sure no error in the configure file..."<<endl;
            exit(0);
        }

        bool save_cfg=true;
        uint8_t x[6]={0};

        try{
            if(vm.count("once")) { save_cfg=false; }
            if(vm.count("dhcp")) { eap_option.dhcp(true); }

            if(vm.count("mode")) { eap_option.mode(static_cast<eap_mode>(vm["mode"].as<int>())); }
            if(vm.count("nic")) { eap_option.nic(vm["nic"].as<string>()); }

            if(vm.count("ip")) { eap_option.ip(str2net(vm["ip"].as<string>())); }
            if(vm.count("mask")) { eap_option.mask(str2net(vm["mask"].as<string>())); }
            if(vm.count("gateway")) { eap_option.gateway(str2net(vm["gateway"].as<string>())); }
            if(vm.count("dns")) { eap_option.dns(str2net(vm["dns"].as<string>())); }
            if(vm.count("mac")) { eap_option.mac(str2mac(vm["mac"].as<string>(),x)); }
            if(vm.count("cast")) { eap_option.cast(str2mac(vm["cast"].as<string>(),x)); }

            if(vm.count("user")) { eap_option.username(vm["user"].as<string>()); }
            if(vm.count("passwd")) { eap_option.password(vm["passwd"].as<string>()); }
        }catch(std::exception &e)
        {
            cout<<e.what()<<endl<<"please make check the options..."<<endl;
            exit(0);
        }

        if(save_cfg) { save_config(&eap_option); }
    }
    show_config(&eap_option);

    pcap_t *pdev=nullptr;
    try{
        get_pcap_device(eap_option.nic(),&pdev);
    }catch(eap_error &e)
    {
        cout<<e.what()<<endl<<"please try again ..."<<endl;
        exit(0);
    }

    Client client(&eap_option,pdev);
    client->prepare();
    try{
        client->start();
        client->packet_loop();
    }catch(eap_error &e)
    {
        cout<<e.what()<<endl;
        exit(0);
    }

    return 0;

}
