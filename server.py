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

import socket
import select
import sys

from Crypto.PublicKey import RSA
from Crypto.Util import randpool
from Crypto.Cipher import AES
import base64
import pickle

from apdu import *

MAX_CONN_REQ = 32        # Max number of connection requests concurrently
MAX_NICK_LEN = 6         # Max nickname length allowed
MAX_MSG_LEN = 100        # Max length of text message
APP_PROTO_VER = "0.1"    # version
SERVER_PORT = 2020       # Define the port to listen
MAX_BUFFER = 1024        # Maximum allowed buffer
SOCKET_LIST = []         # List of sockets connected to the server
USERS_LIST = []          # List of connected users
BLOCK_SIZE = 16          # AES needs a BLOCK_SIZE Of 16, 24 or 32
CIPHER = ''              # AES Cipher

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


def generate_asymm_key():
    random_generator = randpool.RandomPool()
    RSAKey = RSA.generate(1024, random_generator.get_bytes)
    RSAPubKey = RSAKey.publickey()
    return RSAPubKey, RSAKey


def create_socket(SERVER_PORT, host='0.0.0.0', server=False):
    """Returns a socket descriptor
    The default host for hosting/connecting is localhost visible to everybody.
    If the server flag is True, it will bind the host to the specified port.
    If the server flag is False (default), it will connect to the specified
    host:port"""
    # Try to create a TCP socket object named s
    try:
        print 'Creating socket..'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error, msg:
        print 'Failed to create socket. Error code: ' + str(msg[0]) +\
              ' Error' + ' message: ' + msg[1]
        sys.exit()
    # Try to get local hostname
    try:
        if host == '0.0.0.0':
            print 'Setting host as localhost...'
            host = socket.gethostname()
        else:
            print 'Resolving hostname...'
            host = socket.gethostbyname(host)
    except socket.gaierror:
        #could not resolve
        print 'Hostname could not be resolved. Exiting'
        sys.exit()
    # If it's a server, bind the port to a host.
    if server is True:
        # The line below avoids 'port already in use' warning
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Try to bind socket s to the port SERVER_PORT
        try:
            print 'Binding port to hostname..'
            s.bind((host, SERVER_PORT))
        except socket.error, msg:
            print 'Failed to bind socket. Error code: ' + str(msg[0]) +\
                  ' Error' + ' message: ' + msg[1]
            sys.exit()
    # If it's a client, connect it to the server socket.
    else:
        # Try to connect to socket s in the specified port SERVER_PORT
        try:
            s.connect((host, SERVER_PORT))
        except socket.error, msg:
            print 'Failed to connect to socket. Error code: ' + str(msg[0]) +\
                  ' Error message: ' + msg[1]
            sys.exit()

    return s


def message(target_socket, message):
    """Takes a target socket and a message and sends a message to the specified
    socket. This function is supposed to be only used for server notificatoins
    to specific users. For all users, check broadcast.__doc__"""
    # Send the message only to the target
    for sockfd in SOCKET_LIST:
        if sockfd == target_socket:
            try:
                sockfd.send(message)
            # broken socket connection may be, chat client pressed ctrl+c
            # for example
            except socket.error, msg:
                print 'Failed to send message. Error code: ' + str(msg[0]) +\
                      ' Error' + ' message: ' + msg[1]
                sockfd.close()
                SOCKET_LIST.remove(sockfd)
                sys.exit()


def start_listening():
    # This constant is needed in order to know what data block has SYMM_KEY
    FIRST_INCOMING_MESSAGE = True
    global CIPHER

    # Listen to connection requests
    server_socket = create_socket(SERVER_PORT, server=True)
    server_socket.listen(MAX_CONN_REQ)

    print 'Generating Public Key'
    RSAPubKey, RSAPrivKey = generate_asymm_key()

    print '\n[Chat server started on port ' + str(SERVER_PORT) + ']'
    print 'MAX_BUFFER: ' + str(MAX_BUFFER) + ' bytes.'
    print 'Waiting for connections...\n'

    # Add server socket to the list sockets watched by SELECT
    SOCKET_LIST.append(server_socket)

    while True:
        # Get the list of sockets which are ready to be read through select
        try:
            read_sockets, write_sockets, error_sockets = select.select(
                                                SOCKET_LIST, [], [])
        except KeyboardInterrupt:
            print '\nClosing socket..'
            server_socket.close()
            print 'Socket closed.'
            sys.exit(1)
        for sock in read_sockets:
            #New connection
            if sock == server_socket:
                # Server socket is about to accept a new connection
                sockfd, addr = server_socket.accept()
                # Register the client socket descriptor in the SOCKET_LIST
                print '(' + addr[0] + ') connected to chat server.'
                SOCKET_LIST.append(sockfd)
                # Share Public-Key
                print '\n[Symmetric Key Exchange started]'
                print '--> Sending public key..'
                message(sockfd, pickle.dumps(RSAPubKey))
            # Some incoming message from a client
            else:
                # Receive data
                data = sock.recv(MAX_BUFFER)
                if FIRST_INCOMING_MESSAGE:  # Encrypted with Public Key
                    #print 'Encrypted data: ' + data
                    print '--> Receiving encrypted Symmetric Key from client...'
                    symm_key_enc = pickle.loads(data)
                    SYMM_KEY = RSAPrivKey.decrypt(symm_key_enc)
                    print '--> Decrypting Symmetric Key with Private Key..'
                    print '--> Symmetric key exchange was successful.'
                    print '[Symmetric Key Exchange ended]\n'
                    CIPHER = AES.new(SYMM_KEY)

                    # Encrypt SYMM_ACK which is the header
                    data = SYMM_ACK
                    data_enc = EncodeAES(CIPHER, data)
                    # Send SYMM_ACK to confirm Symmetric Key Exchange
                    message(sock, data_enc)
                    FIRST_INCOMING_MESSAGE = False
                else:
                    decoded = DecodeAES(CIPHER, data)
                    # Server info requested
                    if decoded[:2] == REQ_SERVER_INFO:
                        print 'Server Info requested by ' + addr[0]
                        # SHARE_SERVER_INFO is the header
                        msg = SHARE_SERVER_INFO + ',' + str(MAX_CONN_REQ) +\
                              ',' + str(MAX_NICK_LEN) + ',' +\
                              str(MAX_MSG_LEN) + ',' + APP_PROTO_VER
                        msg_enc = EncodeAES(CIPHER, msg)
                        # Sharing server info
                        message(sock, msg_enc)

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print 'Usage: python server.py port'
        sys.exit()
    else:
        try:
            SERVER_PORT = int(sys.argv[1])
        except ValueError:
            print 'Server port must be an integer.'
            sys.exit()
    if SERVER_PORT > 65535:
        print 'Server port must be lower than 65535.'
    else:
        start_listening()
