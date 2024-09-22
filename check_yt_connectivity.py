import socket

s=socket.socket()
s.settimeout(4)
try:
    s.connect(("rr8---sn-gvnuxaxjvh-n8ml.googlevideo.com", 443))
    print("Блокировки по IP адресу нет")
except:
    print("IP адрес заблокирован")

input()