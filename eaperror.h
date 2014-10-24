/*
  eaperror.h: basic elements
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

#include <exception>
/** exceptions for eap */
class eap_error:public std::exception
{
public:
    eap_error():_msg("Unkown error"){}
    eap_error(const char *msg):_msg(msg){}
    virtual const char* what() { return _msg; }
protected:
    const char *_msg;
};

class eap_runtime_error:public eap_error
{
public:
    eap_runtime_error(const char *msg):eap_error(msg){}
};

class eap_logic_error:public eap_error
{
public:
    eap_logic_error(const char *msg):eap_error(msg){}
};

