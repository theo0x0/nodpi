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
import sys
from ctypes import wintypes
from dataclasses import dataclass
from typing import Iterable, List, TypeVar, Union

import ifaddr._shared as shared

# To aid with platform-specific type-checking
assert sys.platform == 'win32'

NO_ERROR = 0
ERROR_BUFFER_OVERFLOW = 111
MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_ADDRESS_LENGTH = 8
AF_UNSPEC = 0


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [('lpSockaddr', ctypes.POINTER(shared.sockaddr)), ('iSockaddrLength', wintypes.INT)]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ('Length', wintypes.ULONG),
    ('Flags', wintypes.DWORD),
    ('Next', ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ('Address', SOCKET_ADDRESS),
    ('PrefixOrigin', ctypes.c_uint),
    ('SuffixOrigin', ctypes.c_uint),
    ('DadState', ctypes.c_uint),
    ('ValidLifetime', wintypes.ULONG),
    ('PreferredLifetime', wintypes.ULONG),
    ('LeaseLifetime', wintypes.ULONG),
    ('OnLinkPrefixLength', ctypes.c_uint8),
]


class IP_ADAPTER_FLAGS_ADDRESS(ctypes.Structure):
    pass


# IP_ADAPTER_ANYCAST_ADDRESS_XP, IP_ADAPTER_MULTICAST_ADDRESS_XP and
# IP_ADAPTER_DNS_SERVER_ADDRESS_XP are almost identical so we use a single structure
# for all of them.
IP_ADAPTER_FLAGS_ADDRESS._fields_ = [
    ('Length', wintypes.ULONG),
    # In IP_ADAPTER_DNS_SERVER_ADDRESS_XP this property is called Reserved and likely not used.
    ('Flags', wintypes.DWORD),
    ('Next', ctypes.POINTER(IP_ADAPTER_FLAGS_ADDRESS)),
    ('Address', SOCKET_ADDRESS),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


MAX_ADAPTER_ADDRESS_LENGTH = 8

IP_ADAPTER_ADDRESSES._fields_ = [
    ('Length', wintypes.ULONG),
    ('IfIndex', wintypes.DWORD),
    ('Next', ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ('AdapterName', ctypes.c_char_p),
    ('FirstUnicastAddress', ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ('FirstAnycastAddress', ctypes.POINTER(IP_ADAPTER_FLAGS_ADDRESS)),
    ('FirstMulticastAddress', ctypes.POINTER(IP_ADAPTER_FLAGS_ADDRESS)),
    ('FirstDnsServerAddress', ctypes.POINTER(IP_ADAPTER_FLAGS_ADDRESS)),
    ('DnsSuffix', ctypes.c_wchar_p),
    ('Description', ctypes.c_wchar_p),
    ('FriendlyName', ctypes.c_wchar_p),
    ('PhysicalAddress', ctypes.c_char * MAX_ADAPTER_ADDRESS_LENGTH),
    ('PhysicalAddressLength', wintypes.ULONG),
    ('Flags', wintypes.ULONG),
    ('Mtu', wintypes.ULONG),
    ('IfType', wintypes.DWORD),
    ('OperStatus', ctypes.c_uint),
    # Windows XP SP1 and later
    ('Ipv6IfIndex', wintypes.DWORD),
    # Windows XP SP1 and later
    ('ZoneIndices', wintypes.DWORD * 16),
]


# Type-checker friendly and more convenient to use counterparts to the ctypes
# structures above.


@dataclass
class IPAdapterAddressWithFlags:
    flags: int
    address: Union[shared.IPv4Ext, shared.IPv6Ext]


@dataclass
class IPAdapterUnicastAddress(IPAdapterAddressWithFlags):
    prefix_origin: int
    suffix_origin: int
    dad_state: int
    valid_lifetime: int
    preferred_lifetime: int
    lease_lifetime: int
    on_link_prefix_length: int


@dataclass
class IPAdapterAddress:
    if_index: int
    adapter_name: str
    unicast_addresses: List[IPAdapterUnicastAddress]
    anycast_addresses: List[IPAdapterAddressWithFlags]
    multicast_addresses: List[IPAdapterAddressWithFlags]
    dns_server_addresses: List[IPAdapterAddressWithFlags]
    dns_suffix: str
    description: str
    friendly_name: str
    physical_address: bytes
    flags: int
    mtu: int
    if_type: int
    oper_status: int
    ipv6_if_index: int
    zone_indices: List[int]
    # Not implemented yet: there's a bunch of extra properties left in IP_ADAPTER_ADDRESSES


iphlpapi = ctypes.windll.LoadLibrary("Iphlpapi")

T = TypeVar('T', IP_ADAPTER_UNICAST_ADDRESS, IP_ADAPTER_FLAGS_ADDRESS)


def gather_linked_list(first: ctypes._Pointer) -> List[T]:
    current = first
    result: List[T] = []
    while current:
        result.append(current.contents)
        current = current.contents.Next
    return result


def get_adapters(include_unconfigured: bool = False) -> Iterable[shared.Adapter]:
    win32_adapters = get_win32_adapters()
    converted = convert_win32_adapters(win32_adapters, include_unconfigured=include_unconfigured)
    return converted


def get_win32_adapters() -> List[IPAdapterAddress]:
    # This function interacts with the OS. It does *not* interpret the results too much,
    # only decodes/deserializes them.

    # Call GetAdaptersAddresses() with error and buffer size handling
    addressbuffersize = wintypes.ULONG(15 * 1024)
    retval = ERROR_BUFFER_OVERFLOW
    while retval == ERROR_BUFFER_OVERFLOW:
        addressbuffer = ctypes.create_string_buffer(addressbuffersize.value)
        retval = iphlpapi.GetAdaptersAddresses(
            wintypes.ULONG(AF_UNSPEC),
            wintypes.ULONG(0),
            None,
            ctypes.byref(addressbuffer),
            ctypes.byref(addressbuffersize),
        )
    if retval != NO_ERROR:
        raise ctypes.WinError()

    # Iterate through adapters fill array
    address_infos: List[IP_ADAPTER_ADDRESSES] = []
    address_info = IP_ADAPTER_ADDRESSES.from_buffer(addressbuffer)
    while True:
        address_infos.append(address_info)
        if not address_info.Next:
            break
        address_info = address_info.Next.contents
    return [
        IPAdapterAddress(
            a.IfIndex,
            # We don't expect non-ascii characters here, so encoding shouldn't matter
            a.AdapterName.decode(),
            [
                IPAdapterUnicastAddress(
                    ua.Flags,
                    shared.sockaddr_to_ip_strict(ua.Address.lpSockaddr),
                    ua.PrefixOrigin,
                    ua.SuffixOrigin,
                    ua.DadState,
                    ua.ValidLifetime,
                    ua.PreferredLifetime,
                    ua.LeaseLifetime,
                    ua.OnLinkPrefixLength,
                )
                for ua in gather_linked_list(a.FirstUnicastAddress)
            ],
            [
                IPAdapterAddressWithFlags(
                    ua.Flags,
                    shared.sockaddr_to_ip_strict(ua.Address.lpSockaddr),
                )
                for ua in gather_linked_list(a.FirstAnycastAddress)
            ],
            [
                IPAdapterAddressWithFlags(
                    ua.Flags,
                    shared.sockaddr_to_ip_strict(ua.Address.lpSockaddr),
                )
                for ua in gather_linked_list(a.FirstMulticastAddress)
            ],
            [
                IPAdapterAddressWithFlags(
                    ua.Flags,
                    shared.sockaddr_to_ip_strict(ua.Address.lpSockaddr),
                )
                for ua in gather_linked_list(a.FirstDnsServerAddress)
            ],
            a.DnsSuffix,
            a.Description,
            a.FriendlyName,
            a.PhysicalAddress[: a.PhysicalAddressLength],
            a.Flags,
            a.Mtu,
            a.IfType,
            a.OperStatus,
            a.Ipv6IfIndex,
            list(a.ZoneIndices),
        )
        for a in address_infos
    ]


def convert_win32_adapters(
    adapters: List[IPAdapterAddress], *, include_unconfigured: bool
) -> List[shared.Adapter]:
    # This function *does not* interact with the OS. It converts raw data returned
    # from the OS to ifaddr adapters.

    # Iterate through unicast addresses
    result: List[shared.Adapter] = []
    for adapter in adapters:
        name = adapter.adapter_name
        nice_name = adapter.description
        index = adapter.if_index

        if adapter.unicast_addresses:
            ips = [
                shared.IP(a.address, a.on_link_prefix_length, adapter.friendly_name)
                for a in adapter.unicast_addresses
            ]
            result.append(shared.Adapter(name, nice_name, ips, index=index))
        elif include_unconfigured:
            result.append(shared.Adapter(name, nice_name, [], index=index))

    return result
