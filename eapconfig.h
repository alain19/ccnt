/*
  eapconfig.h: configure settings
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
#include "eaperror.h"

void init_config(EAPOption *option) throw(eap_runtime_error,eap_logic_error);
void read_config(EAPOption *option) throw(eap_logic_error);
void save_config(const EAPOption *option);
void show_config(const EAPOption *option);
