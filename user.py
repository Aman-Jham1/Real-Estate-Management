from Utils import Block
from RSA import RSA
import getpass
import socket
import pickle, struct


serverPubKey = (98581262173360837326167111125113695068362686677036762762847714161386363356381, 5)

username = input("Enter Username: ")
password = getpass.getpass(prompt="Enter Password: ")
rsa = RSA()
password = rsa.getEncryption(password, serverPubKey[0], serverPubKey[1])#RSA(password, serverPubKey[0], serverPubKey[1])
print(password)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 5000))
print('Client has been assigned socket name ', sock.getsockname())
print(username)
sock.sendall(username.encode())
reply = sock.recv(4096)
print(reply.decode())
pswd = pickle.dumps(password)
sock.sendall(struct.pack("L", len(pswd))+pswd)

reply = sock.recv(4096)
reply = reply.decode()
if reply == 'Authentication Failed':
    print('Authentication Failed')
    exit(1)
if reply == 'Send Block':
    print('Authentication Successful, enter Data for block formation')
    n = input("Number of Fields: ")
    n = int(n)
    fields = {}
    while n:
        k = input("Enter Key value: ")
        v = input("Enter Value for Key: ")
        fields[k]=v
        n-=1
    f = open('Users.txt', 'rb')
    users = pickle.load(f)
    f.close()
    for user in users:
        if user.username == username:
            currUser = user
            break
    f = open('BlockChain.txt', 'rb')
    blocks = pickle.load(f)
    f.close()
    prevHash = blocks[-1].Hash
    block = Block(fields, currUser.username, prevHash)
    data = pickle.dumps(block)
    sock.sendall(struct.pack("L", len(data))+data)
    reply = sock.recv(4096)
    reply = reply.decode()
    print(repr(reply))

sock.close()