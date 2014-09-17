/*
  main.cpp
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
#include <sstream>
#include <string>
#include <signal.h>
#include "dcclient.h"
#include "md5.h"
using namespace std;

namespace{
EAPClient *client=nullptr;
void dying_logoff(int sig)
{
    if(sig!=SIGINT){ return; }
    if(client!=nullptr)
    {
        client->logoff();
    }
    raise(SIGINT);
}
}

int main()
{
	//获取设备信息、用户名、密码等
    auto devs=get_all_devices();
    for(size_t i=0;i<devs.size();++i)
    {
        cout<<i<<": "<<devs[i].desc<<endl;
        //print_mac_addr(devs[i].mac);
    }
    int num=0;
    cout<<"please choose the number:";
    cin>>num;
    string username,password;
    cout<<"please input the username:";
    cin>>username;
    cout<<"please choose the password:";
    cin>>password;

	//获取网卡pcap_t指针，填充dc_tailer字段
    pcap_t *pdev;
    dc_tailer dtailer={1,{0},{0},{0},{0},{0},{0}};
    if(!get_pcap_device(devs[num].name,&pdev,&dtailer))
    {
        cout<<"ERROR in get_pcap_device!"<<endl;
        return 0;
    }
    memcpy(&dtailer.client_ver,global::CLIENT_VER,global::DC_VER_LEN);
    MD5 _md5_;
    md5_str2bytes(_md5_(username),dtailer.usr_md5);

    //监听信号，退出时发送Logoff包
    signal(SIGINT,dying_logoff);
    //开始客户端认证
	client=new DCClient(username,password,pdev,dtailer);
    cout<<"client new done\n";
    dynamic_cast<DCClient*>(client)->init_packets(devs[num].mac);
    cout<<"client init_packets done\n";
    client->start();
    cout<<"client start done\n";
    client->packet_loop();
    return 0;
}
