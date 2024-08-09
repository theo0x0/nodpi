import socket
import threading
import random
port = 8881
import dns.message
import dns.query
import dns.rdatatype

def main():

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen()

    print('Прокси запущено на порту ', port)

    while True:
        conn, _ = server.accept()
        http_data = conn.recv(1500)

        type, target = http_data.split(b"\r\n")[0].split(b" ")[0:2]
        
        if type != b"CONNECT":
            conn.close()
            print(1, type, host, target)
            continue

        host, traget_port = target.split(b":")

        conn.send(b'HTTP/1.1 200 OK\n\n')
        threading.Thread(target=new_conn,
                         args=(conn, host.decode(), int(traget_port),)).start()

def new_conn(conn, host, port):

    ip = ""

    msg = dns.message.make_query(host, "A")
    res = dns.query.udp(msg, "210.0.128.242")
       
    for answer in res.answer:
        if answer.rdtype == dns.rdatatype.A:
            ip = answer[0].address

    if ip == "":
        conn.close()
        return

    sock = socket.socket()
    sock.connect((ip, port))

    if port == 443:
        fragemtn_data(conn, sock)

    #print(host, ip)

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
        fake_length = real_length

        while real_length > 0:
            fake_length = random.randint(1, real_length)
            head = type + bytes.fromhex("03") + random.randbytes(1)

            conn_to.send(head  + int(fake_length).to_bytes(2) + conn.recv(fake_length))
            real_length -= fake_length
            

if __name__ == "__main__":
    main()