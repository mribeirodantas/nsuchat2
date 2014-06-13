#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# This file is part of NSUChat2.
# This module contains information regarding the Application Protocol Data Units
#
# Copyright (©) 2014 Marcel Ribeiro Dantas
#
# <mribeirodantas at fedoraproject.org>
#
# NSUChat2 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# NSUChat2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NSUChat2. If not, see <http://www.gnu.org/licenses/>.

# https://docs.python.org/2/howto/doanddont.html#from-module-import
# does not fit this case. Other files should do:
# from apdu import *

SYMM_ACK = '02'
# First message encrypted with Symmetric Key (AES)
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

SET_NICKNAME = '05'
# Set the entering nickname
"""  -------------------
    | HEADER | NICKNAME |
    |   05   |          |
    |________|__________|"""

ALREADY_USED = '06'
# Chosen nick already used by someone else.
"""  --------
    | HEADER |
    |   06   |
    |________|"""

WELCOME = '07'
# All steps in order to join room were satisfied.
"""  --------
    | HEADER |
    |   07   |
    |________|"""

BROADCAST = '08'
# Message that is supposed to be sent to every connected user.
"""  ------------------
    | HEADER | MESSAGE |
    |   08   |         |
    |________|_________|"""

PRIV_MESSAGE = '09'
# DESTINATION length is calculated by MAX_NICK_LEN
"""  --------------------------------
    | HEADER | DESTINATION | MESSAGE |
    |   09   |             |         |
    |________|_____________|_________|"""

REQ_NICKLIST = '10'
# Request list of online users.
"""  --------
    | HEADER |
    |   10   |
    |________|"""

DISCONNECT = '11'
# Request disconnection from server
"""  --------
    | HEADER |
    |   11   |
    |________|"""

CHANGE_NICKNAME = '12'
# Switch to a nickname
"""  -------------------
    | HEADER | NICKNAME |
    |   12   |          |
    |________|__________|"""

PUB_MESSAGE = '13'
# Send public message
"""  ------------------  or  -----------------------------
    | HEADER | MESSAGE |    | HEADER | NICKNAME | MESSAGE |
    |   13   |         |    |        |          |         |
    |________|_________|    |________|__________|_________|"""

SHARE_NICKLIST = '14'
# Request list of online users.
"""  --------
    | HEADER |
    |   14   |
    |________|"""
