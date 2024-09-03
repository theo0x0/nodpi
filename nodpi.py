import socket
import threading
import random
port = 8881

def main():

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen()

    print(f'Прокси запущено на 127.0.0.1:{port}')

    while True:
        conn, _ = server.accept()
        http_data = conn.recv(1500)

        type, target = http_data.split(b"\r\n")[0].split(b" ")[0:2]
        
        if type != b"CONNECT":
            conn.close()
            #print(1, type, host, target)
            continue

        host, traget_port = target.split(b":")

        conn.send(b'HTTP/1.1 200 OK\n\n')
        threading.Thread(target=new_conn,
                         args=(conn, host.decode(), int(traget_port),)).start()

def new_conn(conn, host, port):

    sock = socket.socket()
    sock.connect((host, port))

    if port == 443:
        fragemtn_data(conn, sock)


    def pipe(conn1, conn2):
        while True:
            try:
                conn2.send(conn1.recv(1500))

            except:
                conn1.close()
                conn2.close()
                break

    threading.Thread(target=pipe, args=(conn, sock)).start()
    threading.Thread(target=pipe, args=(sock, conn)).start()

def fragemtn_data(conn, conn_to):
        type, ver = conn.recv(1), conn.recv(2)

        real_length = int.from_bytes(conn.recv(2), 'big')
        data = conn.recv(real_length)
        parts = []

        while data:
            part_len = random.randint(1, len(data))
            parts.append(type + bytes.fromhex("03") + bytes([random.randint(0, 255)]) + int(part_len).to_bytes(2, byteorder='big')  + data[0:part_len])
            data = data[part_len:]

        data = b''.join(parts)

        while data:
            data_len = random.randint(1, len(data))
            conn_to.send(data[0:data_len])
            data = data[data_len:]

        
            

if __name__ == "__main__":
    main()
