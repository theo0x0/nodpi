import socket
import string
import random

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    return ip

def fake_host(host):
    return "".join(random.choices(string.ascii_letters, k=len(host)-3)) + ".ru"

def get_domain(data):

    data = data[(5 + 4 + 2 + 32):]
    
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