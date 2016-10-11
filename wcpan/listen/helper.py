import contextlib
import errno
import grp
import os
import pwd
import re
import socket
import sys
from typing import Generator, Iterable, List, Type


class TCPEndpoint(object):

    def __init__(self, interface: str, port: int) -> None:
        self._interface = interface
        self._port = port

    def __enter__(self) -> List[socket.socket]:
        self._sockets = bind_sockets(self._port, self._interface, socket.AF_INET)
        return self._sockets

    def __exit__(self, type: Type[Exception], value: Exception, traceback: 'traceback') -> None:
        for skt in self._sockets:
            skt.shutdown(socket.SHUT_WR)
            skt.close()


class UNIXEndpoint(object):

    def __init__(self, path: str) -> None:
        self._path = path
        self._user = 'www-data'
        self._group = 'www-data'

    def __enter__(self) -> None:
        uid = pwd.getpwnam(self._user).pw_uid
        gid = grp.getgrnam(self._group).gr_gid
        self._socket = bind_unix_socket(self._path)
        os.chown(self._path, uid, gid)
        return [self._socket]

    def __exit__(self, type: Type[Exception], value: Exception, traceback: 'traceback') -> None:
        self._socket.shutdown(socket.SHUT_WR)
        self._socket.close()
        os.remove(self._path)


@contextlib.contextmanager
def create_sockets(listen_list: Iterable[Union[int, str]]) -> Generator[List[socket.socket], None, None]:
    endpoint_list = (verify_listen_string(_) for _ in listen_list)
    with contextlib.ExitStack() as stack:
        sockets = (stack.enter_context(_) for _ in endpoint_list)
        sockets = [skt for list_ in sockets for skt in list_]
        yield sockets


# TODO verify unix socket
# TODO file permission
# TODO ipv6 support
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
    if isinstance(port, int):
        m = port
    else:
        m = re.match(r'^[1-9]\d{0,4}$', port)
        if m:
            m = int(port)
    return 1 <= m < 65536


_DEFAULT_BACKLOG = 128


def bind_sockets(port, address=None, family=socket.AF_UNSPEC,
                 backlog=_DEFAULT_BACKLOG, flags=None, reuse_port=False):
    """Creates listening sockets bound to the given port and address.

    Returns a list of socket objects (multiple sockets are returned if
    the given address maps to multiple IP addresses, which is most common
    for mixed IPv4 and IPv6 use).

    Address may be either an IP address or hostname.  If it's a hostname,
    the server will listen on all IP addresses associated with the
    name.  Address may be an empty string or None to listen on all
    available interfaces.  Family may be set to either `socket.AF_INET`
    or `socket.AF_INET6` to restrict to IPv4 or IPv6 addresses, otherwise
    both will be used if available.

    The ``backlog`` argument has the same meaning as for
    `socket.listen() <socket.socket.listen>`.

    ``flags`` is a bitmask of AI_* flags to `~socket.getaddrinfo`, like
    ``socket.AI_PASSIVE | socket.AI_NUMERICHOST``.

    ``reuse_port`` option sets ``SO_REUSEPORT`` option for every socket
    in the list. If your platform doesn't support this option ValueError will
    be raised.
    """
    if reuse_port and not hasattr(socket, 'SO_REUSEPORT'):
        raise ValueError('the platform does not support SO_REUSEPORT')

    sockets = []
    if not address:
        address = None
    if not socket.has_ipv6 and family == socket.AF_UNSPEC:
        # Python can be compiled with --disable-ipv6, which causes
        # operations on AF_INET6 sockets to fail, but does not
        # automatically exclude those results from getaddrinfo
        # results.
        # http://bugs.python.org/issue16208
        family = socket.AF_INET
    if flags is None:
        flags = socket.AI_PASSIVE
    bound_port = None
    for res in set(socket.getaddrinfo(address, port, family, socket.SOCK_STREAM,
                                      0, flags)):
        af, socktype, proto, canonname, sockaddr = res
        if (sys.platform == 'darwin' and address == 'localhost' and
                af == socket.AF_INET6 and sockaddr[3] != 0):
            # Mac OS X includes a link-local address fe80::1%lo0 in the
            # getaddrinfo results for 'localhost'.  However, the firewall
            # doesn't understand that this is a local address and will
            # prompt for access (often repeatedly, due to an apparent
            # bug in its ability to remember granting access to an
            # application). Skip these addresses.
            continue
        try:
            sock = socket.socket(af, socktype, proto)
        except socket.error as e:
            if e.errno == errno.EAFNOSUPPORT:
                continue
            raise
        if os.name != 'nt':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if reuse_port:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if af == socket.AF_INET6:
            # On linux, ipv6 sockets accept ipv4 too by default,
            # but this makes it impossible to bind to both
            # 0.0.0.0 in ipv4 and :: in ipv6.  On other systems,
            # separate sockets *must* be used to listen for both ipv4
            # and ipv6.  For consistency, always disable ipv4 on our
            # ipv6 sockets and use a separate ipv4 socket when needed.
            #
            # Python 2.x on windows doesn't have IPPROTO_IPV6.
            if hasattr(socket, "IPPROTO_IPV6"):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        # automatic port allocation with port=None
        # should bind on the same port on IPv4 and IPv6
        host, requested_port = sockaddr[:2]
        if requested_port == 0 and bound_port is not None:
            sockaddr = tuple([host, bound_port] + list(sockaddr[2:]))

        sock.setblocking(0)
        sock.bind(sockaddr)
        bound_port = sock.getsockname()[1]
        sock.listen(backlog)
        sockets.append(sock)
    return sockets


def bind_unix_socket(file_, mode=0o600, backlog=_DEFAULT_BACKLOG):
    """Creates a listening unix socket.

    If a socket with the given name already exists, it will be deleted.
    If any other file with that name exists, an exception will be
    raised.

    Returns a socket object (not a list of socket objects like
    `bind_sockets`)
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(0)
    try:
        st = os.stat(file_)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise
    else:
        if stat.S_ISSOCK(st.st_mode):
            os.remove(file_)
        else:
            raise ValueError('File %s exists and is not a socket', file_)
    sock.bind(file_)
    os.chmod(file_, mode)
    sock.listen(backlog)
    return sock
