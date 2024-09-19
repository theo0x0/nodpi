

async def proxy_conn(r, w):

    http_data = await r.read(1500)

    type, target = http_data.split(b"\r\n")[0].split(b" ")[0:2]
    host, port = target.split(b":")
    port = int(port)

    if type != b"CONNECT":
        throw
    
    w.write(b'HTTP/1.1 200 OK\n\n')
    await w.drain()

    await make_pipe(r, w, host, port)
    