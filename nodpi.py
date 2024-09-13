import socket
import threading
import random
import asyncio

port = 8881
blocked = open("russia-blacklist.txt", "br").read().split()

async def main():
    server = await asyncio.start_server(new_conn, '127.0.0.1', port)
    print(f'Прокси запущено на 127.0.0.1:{port}')
    await server.serve_forever()

async def pipe(reader, writer):
    while not reader.at_eof() and not writer.is_closing():
        try:
            writer.write(await reader.read(1500))
            await writer.drain()
        except:
            break

    writer.close()

async def new_conn(local_reader, local_writer):
    http_data = await local_reader.read(1500)
    type, target = http_data.split(b"\r\n")[0].split(b" ")[0:2]
    
    if type != b"CONNECT":
        local_writer.close()
        return

    try:
        host, port = target.split(b":")
    except:
        local_writer.close()
        return

    local_writer.write(b'HTTP/1.1 200 OK\n\n')
    await local_writer.drain()

    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
    except:
        local_writer.close()
        return

    if port == b'443':
        await fragemtn_data(local_reader, remote_writer)

    asyncio.create_task(pipe(local_reader, remote_writer))
    asyncio.create_task(pipe(remote_reader, local_writer))

async def fragemtn_data(local_reader, remote_writer):
    head = await local_reader.read(5)

    data = await local_reader.read(1500)
    parts = []


    if all([data.find(site) == -1 for site in blocked]):
        remote_writer.write(head + data)
        await remote_writer.drain()

        return

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
