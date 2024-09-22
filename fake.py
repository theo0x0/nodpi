
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import AsyncSniffer, sendp
from os import urandom
from nodpi import config
import asyncio

ports = []
packets = {}
ttl = {}

async def send_packet(data, to_port):
    await asyncio.sleep(0.2)
    
    if not packets.get(to_port) or not ttl.get(to_port):
        return False

    if ttl.get(to_port):
        if ttl[to_port] > 64:
            distance=128-ttl[to_port]
        else:
            distance=64-ttl[to_port]
    else:
        return False


    packets[to_port]["p"].payload.chksum=None
    packets[to_port]["p"].payload.len=None
    packets[to_port]["p"].payload.payload.chksum= None
    packets[to_port]["p"].payload.payload.flags = packets[to_port]["p"].payload.payload.flags.value | 8
    packets[to_port]["p"].payload.payload.seq = packets[to_port]["ack"]

    if config["fake_mode"] == 1:
        packets[to_port]["p"].payload.ttl=distance - 3
        packets[to_port]["p"].payload.payload.payload = Raw(data)

    elif config["fake_mode"] == 2:
        packets[to_port]["p"].payload.payload.seq += 1000
        packets[to_port]["p"].payload.payload.payload = Raw(urandom(30) + data) 

    elif config["fake_mode"] == 3:
        packets[to_port]["p"].payload.payload.seq -= 1000
        packets[to_port]["p"].payload.payload.payload = Raw(urandom(30) + data) 

    elif config["fake_mode"] == 4:
        packets[to_port]["p"].payload.dst = "8.8.8.8"
        packets[to_port]["p"].payload.payload.payload = Raw(data)

    elif config["fake_mode"] == 5:
        packets[to_port]["p"].payload.payload.dport = 53
        packets[to_port]["p"].payload.payload.payload = Raw(data)

    elif config["fake_mode"] == 6:
        packets[to_port]["p"].payload.src = "8.8.8.8"
        packets[to_port]["p"].payload.payload.payload = Raw(data)

    else:
        return False

    sendp(packets[to_port]["p"].build(), verbose=False)

    ports.remove(to_port)
    del packets[to_port]

    if config["debug"]:
        print("Фейковый пакет отправлен")

    return True

def listen_interface(p):

        ip = p.payload
        tcp = ip.payload


        if ip.name != "IP":
            return

        if tcp.name != "TCP":
            return
        
        if tcp.sport in ports:
            packets[tcp.sport] = {}
            packets[tcp.sport]["p"] = p
            packets[tcp.sport]["ack"] = tcp.seq + len(tcp.payload)
            
        
        ttl[tcp.dport] = ip.ttl
            
        del tcp
        del ip
