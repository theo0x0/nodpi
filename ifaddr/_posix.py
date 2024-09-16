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


import os
import ctypes.util
import ipaddress
import collections
import socket
import sys

from typing import Dict, Iterable, Optional

import ifaddr._shared as shared

# from ifaddr._shared import sockaddr, Interface, sockaddr_to_ip, ipv6_prefixlength

# To aid with platform-specific type-checking
assert sys.platform != 'win32'


class ifaddrs(ctypes.Structure):
    pass


ifaddrs._fields_ = [
    ('ifa_next', ctypes.POINTER(ifaddrs)),
    ('ifa_name', ctypes.c_char_p),
    ('ifa_flags', ctypes.c_uint),
    ('ifa_addr', ctypes.POINTER(shared.sockaddr)),
    ('ifa_netmask', ctypes.POINTER(shared.sockaddr)),
]

libc = ctypes.CDLL(ctypes.util.find_library("socket" if os.uname()[0] == "SunOS" else "c"), use_errno=True)


def get_adapters(include_unconfigured: bool = False) -> Iterable[shared.Adapter]:
    addr0 = addr = ctypes.POINTER(ifaddrs)()
    retval = libc.getifaddrs(ctypes.byref(addr))
    if retval != 0:
        eno = ctypes.get_errno()
        raise OSError(eno, os.strerror(eno))

    ips: Dict[str, shared.Adapter] = collections.OrderedDict()

    def add_ip(adapter_name: str, ip: Optional[shared.IP]) -> None:
        if adapter_name not in ips:
            index: Optional[int] = None
            try:
                index = socket.if_nametoindex(adapter_name)
            except (OSError, AttributeError):
                pass
            ips[adapter_name] = shared.Adapter(adapter_name, adapter_name, [], index=index)
        if ip is not None:
            ips[adapter_name].ips.append(ip)

    while addr:
        name = addr.contents.ifa_name.decode(encoding='UTF-8')
        ip_addr = shared.sockaddr_to_ip(addr.contents.ifa_addr)
        if ip_addr:
            if addr.contents.ifa_netmask and not addr.contents.ifa_netmask.contents.sa_familiy:
                addr.contents.ifa_netmask.contents.sa_familiy = addr.contents.ifa_addr.contents.sa_familiy
            netmask = shared.sockaddr_to_ip(addr.contents.ifa_netmask)
            if isinstance(netmask, shared.IPv6Ext):
                prefixlen = shared.ipv6_prefixlength(netmask.address)
            else:
                assert netmask is not None, f'sockaddr_to_ip({addr.contents.ifa_netmask}) returned None'
                netmaskStr = str('0.0.0.0/' + str(netmask.address))
                prefixlen = ipaddress.IPv4Network(netmaskStr).prefixlen
            ip = shared.IP(ip_addr, prefixlen, name)
            add_ip(name, ip)
        else:
            if include_unconfigured:
                add_ip(name, None)
        addr = addr.contents.ifa_next

    libc.freeifaddrs(addr0)

    return ips.values()
