# Copyright (c) 2014 Stefan C. Mueller

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.


import ctypes
import socket
import ipaddress
from dataclasses import dataclass

from typing import List, Optional, Union


class Adapter(object):
    """
    Represents a network interface device controller (NIC), such as a
    network card. An adapter can have multiple IPs.

    On Linux aliasing (multiple IPs per physical NIC) is implemented
    by creating 'virtual' adapters, each represented by an instance
    of this class. Each of those 'virtual' adapters can have both
    a IPv4 and an IPv6 IP address.
    """

    def __init__(self, name: str, nice_name: str, ips: List['IP'], index: Optional[int] = None) -> None:
        #: Unique name that identifies the adapter in the system.
        #: On Linux this is of the form of `eth0` or `eth0:1`, on
        #: Windows it is a UUID in string representation, such as
        #: `{846EE342-7039-11DE-9D20-806E6F6E6963}`.
        self.name = name

        #: Human readable name of the adpater. On Linux this
        #: is currently the same as :attr:`name`. On Windows
        #: this is the name of the device.
        self.nice_name = nice_name

        #: List of :class:`ifaddr.IP` instances in the order they were
        #: reported by the system.
        self.ips = ips

        #: Adapter index as used by some API (e.g. IPv6 multicast group join).
        self.index = index

    def __repr__(self) -> str:
        return "Adapter(name={name}, nice_name={nice_name}, ips={ips}, index={index})".format(
            name=repr(self.name), nice_name=repr(self.nice_name), ips=repr(self.ips), index=repr(self.index)
        )


# Technically we don't need this wrapper but when dealing with an IPv4, IPv6 union it's nice
# to be able to unconditionally access the "address" property on it.
@dataclass
class IPv4Ext:
    address: ipaddress.IPv4Address


@dataclass
class IPv6Ext:
    address: ipaddress.IPv6Address
    flowinfo: int
    scope_id: int


class IP(object):
    """
    Represents an IP address of an adapter.
    """

    def __init__(self, ip: Union[IPv4Ext, IPv6Ext], network_prefix: int, nice_name: str) -> None:
        #: IP address. For IPv4 addresses this is a string in
        #: "xxx.xxx.xxx.xxx" format. For IPv6 addresses this
        #: is a three-tuple `(ip, flowinfo, scope_id)`, where
        #: `ip` is a string in the usual collon separated
        #: hex format.
        self.ip = (str(ip.address), ip.flowinfo, ip.scope_id) if isinstance(ip, IPv6Ext) else str(ip.address)

        #: Number of bits of the IP that represent the
        #: network. For a `255.255.255.0` netmask, this
        #: number would be `24`.
        self.network_prefix = network_prefix

        #: Human readable name for this IP.
        #: On Linux is this currently the same as the adapter name.
        #: On Windows this is the name of the network connection
        #: as configured in the system control panel.
        self.nice_name = nice_name

    @property
    def is_IPv4(self) -> bool:
        """
        Returns `True` if this IP is an IPv4 address and `False`
        if it is an IPv6 address.
        """
        return not isinstance(self.ip, tuple)

    @property
    def is_IPv6(self) -> bool:
        """
        Returns `True` if this IP is an IPv6 address and `False`
        if it is an IPv4 address.
        """
        return isinstance(self.ip, tuple)

    def __repr__(self) -> str:
        return "IP(ip={ip}, network_prefix={network_prefix}, nice_name={nice_name})".format(
            ip=repr(self.ip), network_prefix=repr(self.network_prefix), nice_name=repr(self.nice_name)
        )


import sys

if sys.platform == "darwin" or sys.platform.startswith("freebsd") or sys.platform.startswith("openbsd"):
    # BSD derived systems use marginally different structures
    # than either Linux or Windows.
    # I still keep it in `shared` since we can use
    # both structures equally.

    class sockaddr(ctypes.Structure):
        _fields_ = [
            ('sa_len', ctypes.c_uint8),
            ('sa_familiy', ctypes.c_uint8),
            ('sa_data', ctypes.c_uint8 * 14),
        ]

    class sockaddr_in(ctypes.Structure):
        _fields_ = [
            ('sa_len', ctypes.c_uint8),
            ('sa_familiy', ctypes.c_uint8),
            ('sin_port', ctypes.c_uint16),
            ('sin_addr', ctypes.c_uint8 * 4),
            ('sin_zero', ctypes.c_uint8 * 8),
        ]

    class sockaddr_in6(ctypes.Structure):
        _fields_ = [
            ('sa_len', ctypes.c_uint8),
            ('sa_familiy', ctypes.c_uint8),
            ('sin6_port', ctypes.c_uint16),
            ('sin6_flowinfo', ctypes.c_uint32),
            ('sin6_addr', ctypes.c_uint8 * 16),
            ('sin6_scope_id', ctypes.c_uint32),
        ]

else:

    class sockaddr(ctypes.Structure):
        _fields_ = [('sa_familiy', ctypes.c_uint16), ('sa_data', ctypes.c_uint8 * 14)]

    class sockaddr_in(ctypes.Structure):
        _fields_ = [
            ('sin_familiy', ctypes.c_uint16),
            ('sin_port', ctypes.c_uint16),
            ('sin_addr', ctypes.c_uint8 * 4),
            ('sin_zero', ctypes.c_uint8 * 8),
        ]

    class sockaddr_in6(ctypes.Structure):
        _fields_ = [
            ('sin6_familiy', ctypes.c_uint16),
            ('sin6_port', ctypes.c_uint16),
            ('sin6_flowinfo', ctypes.c_uint32),
            ('sin6_addr', ctypes.c_uint8 * 16),
            ('sin6_scope_id', ctypes.c_uint32),
        ]


def sockaddr_to_ip(sockaddr_ptr: ctypes._Pointer) -> Optional[Union[IPv4Ext, IPv6Ext]]:
    if sockaddr_ptr:
        if sockaddr_ptr.contents.sa_familiy == socket.AF_INET:
            ipv4 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(sockaddr_in)).contents
            ippacked = bytes(ipv4.sin_addr)
            return IPv4Ext(ipaddress.IPv4Address(ippacked))
        elif sockaddr_ptr.contents.sa_familiy == socket.AF_INET6:
            ipv6 = ctypes.cast(sockaddr_ptr, ctypes.POINTER(sockaddr_in6)).contents
            ippacked = bytes(ipv6.sin6_addr)
            return IPv6Ext(
                address=ipaddress.IPv6Address(ippacked),
                flowinfo=ipv6.sin6_flowinfo,
                scope_id=ipv6.sin6_scope_id,
            )
    return None


def sockaddr_to_ip_strict(sockaddr_ptr: ctypes._Pointer) -> Union[IPv4Ext, IPv6Ext]:
    """A version of sockaddr_to_ip that raises an exception instead of returning None."""
    result = sockaddr_to_ip(sockaddr_ptr)
    assert result is not None
    return result


def ipv6_prefixlength(address: ipaddress.IPv6Address) -> int:
    prefix_length = 0
    address_as_int = int(address)
    for i in range(address.max_prefixlen):
        if address_as_int >> i & 1:
            prefix_length = prefix_length + 1
    return prefix_length
