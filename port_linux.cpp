/*
  port_linux.cpp: linux related implements
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

#ifdef WIN32  
#error "only for linux implements"
#endif

#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>

#include <cstring>
using std::strcpy;
using std::memcpy;

#include "eapnic.h"
#include "eaputility.h"

const std::vector<nic> get_nics() throw(eap_runtime_error)
{
	int fd=socket(AF_INET, SOCK_DGRAM, 0);
    if(fd<0)
    {
		close(fd);
        throw eap_runtime_error("socket failed");
    }

    std::vector<nic> all_nics;
	struct if_nameindex *devs=if_nameindex();
    for(auto p=devs;p->if_index!=0;p++)
    {
		nic x(p->if_name,p->if_name);
		
		struct ifreq ifr;
        strcpy(ifr.ifr_name, p->if_name);
        
		if(ioctl(fd, SIOCGIFHWADDR, &ifr)<0)
        {
			throw eap_runtime_error("itoclt SIOCGIFHWADDR failed");
        }
        auto hwaddr=ifr.ifr_hwaddr;
        memcpy(x._mac,hwaddr.sa_data,6);

        if(ioctl(fd, SIOCGIFADDR, &ifr)<0)
        {
			throw eap_runtime_error("itoclt SIOCGIFADDR failed");
        }
        auto addr=ifr.ifr_addr;
		x._ip=reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr.s_addr;

        if(ioctl(fd, SIOCGIFNETMASK, &ifr)<0)
        {
			throw eap_runtime_error("itoclt SIOCGIFNETMASK failed");
        }
        auto netmask=ifr.ifr_netmask;
		x._mask=reinterpret_cast<struct sockaddr_in*>(&netmask)->sin_addr.s_addr;
        
		all_nics.push_back(x);
    }
    if_freenameindex(devs);
	close(fd);
    return all_nics;
}

bool enter_running()
{
	sem_t *sem_ccnt = sem_open(SEM_CCNT_NAME, O_CREAT|O_EXCL, 0644, 1);
    return sem_ccnt == SEM_FAILED ? false : true;
}

void leave_running()
{
	sem_unlink(SEM_CCNT_NAME);
}
