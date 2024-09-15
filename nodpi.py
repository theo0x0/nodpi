import socket
import threading
import random
import asyncio
from dnslib.server import DNSServer, BaseResolver
from dnslib.dns import DNSRecord, RR, QTYPE, A, DNSQuestion


port = 8881
blocked = open("russia-blacklist.txt", "br").read().split()
tasks = []

def get_domain(data):

    data = data[(4 + 2 + 32):]
    
    len2 = int.from_bytes(data[:1], byteorder='big')
    data = data[(1 + len2):]

    len_2 = int.from_bytes(data[:2], byteorder='big')
    data = data[2 + len_2:]
    
    len2 = int.from_bytes(data[:1], byteorder='big')
    data = data[(1 + len2):]

    ext_len = int.from_bytes(data[:2], byteorder='big')
    data = data[2:]


    offset = 0
    while offset < ext_len:
        type = int.from_bytes(data[offset:offset+2], byteorder='big')
        len2 = int.from_bytes(data[offset+2:offset+4], byteorder='big')

        if type != 0:
            offset += len2 + 4
            continue

        return data[offset+4+2+1+2:offset+len2+4].decode()
        
def is_blocked(host):
    for site in blocked:
        if host.find(site) >= 0:
            return True
            
    return False

class LocalResolve(BaseResolver):
    def resolve(self,request,handler):
        
        q = str(request.questions[0].qname).encode()
        
        if is_blocked(q):
            res = request.reply()
            res.add_answer(RR(request.questions[0].qname,QTYPE.A,rdata=A("127.0.0.1"),ttl=60))
            
            return res
        
        return DNSRecord.parse(request.send("9.9.9.9"))


async def main():
    proxy_server = await asyncio.start_server(new_conn, '127.0.0.1', port)
    print(f'Прокси запущено на 127.0.0.1:{port}')

    ssl_server = await asyncio.start_server(new_conn, '127.0.0.1', 443)

    dns_server = DNSServer(LocalResolve())
    dns_server.start_thread()

    print(f'DNS сервер запущен 127.0.0.1')

    await proxy_server.serve_forever()

async def pipe(reader, writer):
    while not reader.at_eof() and not writer.is_closing():
        try:
            writer.write(await reader.read(1500))
            await writer.drain()
        except:
            break


    writer.close()

async def connect_proxy(r, w):
    http_data = await r.read(1500)

    type, target = http_data.split(b"\r\n")[0].split(b" ")[0:2]
    host, port = target.split(b":")

    if type != b"CONNECT":
        throw
    
    w.write(b'HTTP/1.1 200 OK\n\n')
    await w.drain()

    return host.decode(), int(port)
    

def resolve(host, server):
    q = DNSRecord()
    q.add_question(DNSQuestion(host))
    
    for r in DNSRecord.parse(q.send(server, timeout=5)).rr:
        if r.rtype == 1:
            return str(r.rdata)
    
async def new_conn(local_reader, local_writer):

    _, local_port = local_writer.transport.get_extra_info('socket').getsockname()

    try:
        if local_port == 8881:
            host, port = await connect_proxy(local_reader, local_writer)
            ip = resolve(host, "127.0.0.1")

    except:
        local_writer.close()
        return



    head = await local_reader.read(5)
    data = await local_reader.read(1500)
    
        
    try:

        if local_port == 443:
            host = get_domain(data)
            port = 443

            ip = resolve(host, "9.9.9.9")

        remote_reader, remote_writer = await asyncio.open_connection(ip, port)
    except:
        local_writer.close()
        return

    

    if local_port == 443:
        await fragemtn_data(data, local_reader, remote_writer)
    else:
        remote_writer.write(head + data)
        await remote_writer.drain()

    tasks.append(asyncio.create_task(pipe(local_reader, remote_writer)))
    tasks.append(asyncio.create_task(pipe(remote_reader, local_writer)))

async def fragemtn_data(data, local_reader, remote_writer):

    parts = []

    while data:
        part_len = random.randint(1, len(data))
        parts.append(bytes.fromhex("1603") + bytes([random.randint(0, 255)]) + int(part_len).to_bytes(2, byteorder='big') + data[0:part_len])
        
        data = data[part_len:]

    data = b''.join(parts)

    while data:
        data_len = random.randint(1, len(data))
        remote_writer.write(data[0:data_len])
        await remote_writer.drain()

        data = data[data_len:]
            

if __name__ == "__main__":
    asyncio.run(main())
