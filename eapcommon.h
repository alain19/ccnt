/*
  eapcommon.h: common operations of different clients
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

#include "eapoption.h"
#include "digitalchina.h"

class Client
{
public:
	Client(EAPOption *option, pcap_t *pdev):_client(nullptr),_good(false)
	{
		switch(option->mode())
    	{
        	case eap_mode::Standard:
			{
				_client=new EAPClient(option,pdev);
				_good=true;
			}break;
        	case eap_mode::DigitalChina:
			{
				_client=new DCClient(option,pdev);
				_good=true;
			}break;
		}
	}

	~Client()
	{
		if(_client!=nullptr) { delete _client; }
	}

	bool good() const { return _good; }

	EAPClient* operator->() { return _client; }

private:
	EAPClient *_client;
	bool _good;
};
