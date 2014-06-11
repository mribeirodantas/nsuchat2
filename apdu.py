#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# This file is part of PySafeChat.
# This module contains the functions related to establishing connections.
#
# Copyright (©) 2014 Marcel Ribeiro Dantas
#
# <mribeirodantas at fedoraproject.org>
#
# PySafeChat is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# PySafeChat is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PySafeChat. If not, see <http://www.gnu.org/licenses/>.

# https://docs.python.org/2/howto/doanddont.html#from-module-import
# does not fit this case. Other files should do:
# from apdu import *

SYMM_ACK = '02'
"""  --------
    | HEADER |
    |   02   |
    |________|"""

REQ_SERVER_INFO = '03'
"""  --------
    | HEADER |
    |   03   |
    |________|"""

SHARE_SERVER_INFO = '04'
"""  --------------------------------------------------------------------
    | HEADER | MAX_CONN_REQ | MAX_NICK_LEN | MAX_MSG_LEN | APP_PROTO_VER |
    |   04   |              |              |             |               |
    |________|______________|______________|_____________|_______________|"""

CHANGE_NICKNAME = '05'
"""  -------------------
    | HEADER | NICKNAME |
    |   03   |          |
    |________|__________|"""

ALREADY_USED = '06'
"""  --------
    | HEADER |
    |   06   |
    |________|"""

WELCOME = '07'
"""  --------
    | HEADER |
    |   07   |
    |________|"""

BROADCAST = '08'
"""  ------------------
    | HEADER | MESSAGE |
    |   08   |         |
    |________|_________|"""

PRIV_MESSAGE = '09'
CHANGE_NICK = '10'
REQ_NICKLIST = '11'
