
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import AsyncSniffer, sendp
import time
from os import urandom
import random

ports = []
packets = {}
ttl = {}

def send_packet(to_port):
    
    if not packets.get(to_port):
        return

    if ttl.get(to_port):
        if ttl[to_port] > 64:
            distance=128-ttl[to_port]
        else:
            distance=64-ttl[to_port]
    else:
        distance=5

    packets[to_port]["p"].payload.chksum=None
    packets[to_port]["p"].payload.len=None
    packets[to_port]["p"].payload.ttl=random.randint(1, distance)

    packets[to_port]["p"].payload.payload.chksum=None
    packets[to_port]["p"].payload.payload.seq = packets[to_port]["ack"]
    packets[to_port]["p"].payload.payload.payload = Raw(urandom(random.randint(1, len(packets[to_port]["p"].payload.payload.payload) + 1)))
    packets[to_port]["p"].payload.payload.flags = packets[to_port]["p"].payload.payload.flags.value | 8

    sendp(packets[to_port]["p"].build(), verbose=False)

def listen_interface(p):

        ip = p.payload
        tcp = ip.payload


        if ip.name != "IP":
            return

        if tcp.name != "TCP":
            return

        
        if tcp.sport in ports:
            if packets.get(tcp.sport) == None:
                packets[tcp.sport] = {}

            packets[tcp.sport]["p"] = p
            packets[tcp.sport]["ack"] = tcp.seq + len(tcp.payload)
            
        if tcp.dport in ports:
            ttl[tcp.dport] = ip.ttl
            
        del tcp
        del ip
