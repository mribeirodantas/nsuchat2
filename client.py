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

import select
import sys

import pickle

from server import create_socket

SOCKET_LIST = []         # List of sockets connected to the server
VERSION = 0.1            # Client Application Protocol Version
nickname = ''            # User nickname
serverPort = ''          # Port to connect
FIRST_READING = True     # First reading
MAX_BUFFER = 1024

if __name__ == "__main__":
    if len(sys.argv) == 1:
        try:
            print "Please, answer the following questions."
            while len(nickname) == 0 or nickname[0] == ' ':
                nickname = raw_input("Nickname: ")
            server_ip = raw_input("Server IP/Name: ")
            if server_ip == '':
                print 'Using localhost...'
                server_ip = '0.0.0.0'
            while len(serverPort) == '' or serverPort == '':
                serverPort = raw_input("Server Port: ")
            serverPort = int(serverPort)
        except KeyboardInterrupt:
            print "\nQuitting.."
            sys.exit()
    elif len(sys.argv) != 3:
        print 'Usage: python client.py nickname server:port'
        sys.exit()
    else:
        try:
            nickname = sys.argv[1]
            serverPort = sys.argv[2]
            # If server was informed in the commandline argument
            if len(serverPort.split(':')) == 2:
                serverPort = int(serverPort.split(':')[1])
                server_ip = serverPort.split(':')[0]
            else:
                serverPort = int(serverPort)
                server_ip = '0.0.0.0'
        except ValueError:
            print 'Server port must be an integer.'
            sys.exit()

    if serverPort > 65535:
        print 'Server port must be lower than 65535.'
    else:
        client_socket = create_socket(serverPort, server_ip)
        print 'Connected to the chat server'

    while True:
        try:
            SOCKET_LIST = [sys.stdin, client_socket]
            # Get the list sockets which are readable
            read_sockets, write_sockets, error_sockets = select.select(
                                                        SOCKET_LIST, [], [])
        except KeyboardInterrupt:
            print "\nQuitting..."
            sys.exit()
        for sock in read_sockets:
            #incoming message from remote server
            if sock == client_socket:
                data = sock.recv(MAX_BUFFER)
                if not data:
                    print '\nDisconnected from chat server'
                    sys.exit()
                else:
                    if FIRST_READING:
                        public_key = pickle.loads(data)
                        secretText = public_key.encrypt("Palavra-passe", 32)
                        sock.send(pickle.dumps(secretText))
                        FIRST_READING = False
