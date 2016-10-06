import argparse
import contextlib
import grp
import os
import pwd
import re
import socket
import sys

import tornado.netutil as tn


class TCPEndpoint(object):

    def __init__(self, interface, port):
        self._interface = interface
        self._port = port

    def __enter__(self):
        self._sockets = tn.bind_sockets(self._port, self._interface, socket.AF_INET)
        return self._sockets

    def __exit__(self, exc_type, exc_value, traceback):
        for skt in self._sockets:
            skt.close()


class UNIXEndpoint(object):

    def __init__(self, path):
        self._path = path
        self._user = 'www-data'
        self._group = 'www-data'

    def __enter__(self):
        uid = pwd.getpwnam(self._user).pw_uid
        gid = grp.getgrnam(self._group).gr_gid
        self._socket = tn.bind_unix_socket(self._path)
        os.chown(self._path, uid, gid)
        return [self._socket]

    def __exit__(self, exc_type, exc_value, traceback):
        self._socket.close()
        os.remove(self._path)


@contextlib.contextmanager
def create_sockets(listen_list):
    endpoint_list = (verify_listen_string(_) for _ in listen_list)
    with contextlib.ExitStack() as stack:
        sockets = (stack.enter_context(_) for _ in endpoint_list)
        sockets = [skt for list_ in sockets for skt in list_]
        yield sockets


# TODO verify unix socket
# TODO file permission
def verify_listen_string(listen):
    # port only
    if verify_port(listen):
        return TCPEndpoint('0.0.0.0', int(listen))
    # ipv4:port
    m = listen.split(':', 1)
    if len(m) == 2 and verify_ipv4(m[0]) and verify_port(m[1]):
        return TCPEndpoint(m[0], int(m[1]))
    # path of unix socket
    return UNIXEndpoint(listen)


def verify_ipv4(ipv4):
    m = r'(0|([1-9][0-9]{0,2}))'
    m = re.match(r'^{0}\.{0}\.{0}\.{0}$'.format(m), ipv4)
    if m:
        m = m.groups()
        m = [m[_] for _ in range(0, len(m), 2)]
        m = [0 <= int(_) < 256 for _ in m]
        m = all(m)
        if m:
            return True
    return False


def verify_port(port):
    m = re.match(r'^[1-9]\d{0,4}$', port)
    if m:
        m = int(port)
        if 1 <= m < 65536:
            return True
    return False
