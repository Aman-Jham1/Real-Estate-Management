import datetime
import pickle
import struct
import hashlib
import json
import socket
from threading import Thread
import os, sys
import random
from RSA import RSA
import pandas as pd

prKey = (98581262173360837326167111125113695068362686677036762762847714161386363356381, 39432504869344334930466844450045478027093153642958253734301565008685708450381)
IP =   [58, 50, 42, 34, 26, 18, 10, 2, 
        60, 52, 44, 36, 28, 20, 12, 4, 
        62, 54, 46, 38, 30, 22, 14, 6, 
        64, 56, 48, 40, 32, 24, 16, 8, 
        57, 49, 41, 33, 25, 17, 9, 1, 
        59, 51, 43, 35, 27, 19, 11, 3, 
        61, 53, 45, 37, 29, 21, 13, 5, 
        63, 55, 47, 39, 31, 23, 15, 7]

Dbox = [32, 1 , 2 , 3 , 4 , 5 , 4 , 5, 
        6 , 7 , 8 , 9 , 8 , 9 , 10, 11, 
        12, 13, 12, 13, 14, 15, 16, 17, 
        16, 17, 18, 19, 20, 21, 20, 21, 
        22, 23, 24, 25, 24, 25, 26, 27, 
        28, 29, 28, 29, 30, 31, 32, 1]

SP =   [16,  7, 20, 21,
        29, 12, 28, 17, 
        1, 15, 23, 26, 
        5, 18, 31, 10, 
        2,  8, 24, 14, 
        32, 27,  3,  9, 
        19, 13, 30,  6, 
        22, 11,  4, 25]

Sbox =  [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], 
            [ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], 
            [ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], 
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ]],
                
            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], 
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], 
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], 
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ]], 
        
            [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], 
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], 
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], 
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ]], 
            
            [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], 
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], 
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], 
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ], 
            
            [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], 
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], 
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], 
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ]], 
            
            [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], 
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], 
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], 
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ], 
            
            [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], 
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], 
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], 
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ], 
            
            [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], 
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], 
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], 
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ] ]

FP =   [40, 8, 48, 16, 56, 24, 64, 32, 
        39, 7, 47, 15, 55, 23, 63, 31, 
        38, 6, 46, 14, 54, 22, 62, 30, 
        37, 5, 45, 13, 53, 21, 61, 29, 
        36, 4, 44, 12, 52, 20, 60, 28, 
        35, 3, 43, 11, 51, 19, 59, 27, 
        34, 2, 42, 10, 50, 18, 58, 26, 
        33, 1, 41, 9, 49, 17, 57, 25]

PC1 =  [57, 49, 41, 33, 25, 17, 9, 
        1, 58, 50, 42, 34, 26, 18, 
        10, 2, 59, 51, 43, 35, 27, 
        19, 11, 3, 60, 52, 44, 36, 
        63, 55, 47, 39, 31, 23, 15, 
        7, 62, 54, 46, 38, 30, 22, 
        14, 6, 61, 53, 45, 37, 29, 
        21, 13, 5, 28, 20, 12, 4]

ST =   [1, 1, 2, 2, 
        2, 2, 2, 2, 
        1, 2, 2, 2, 
        2, 2, 2, 1]

PC2 =  [14, 17, 11, 24, 1, 5, 
        3, 28, 15, 6, 21, 10, 
        23, 19, 12, 4, 26, 8, 
        16, 7, 27, 20, 13, 2, 
        41, 52, 31, 37, 47, 55, 
        30, 40, 51, 45, 33, 48, 
        44, 49, 39, 56, 34, 53, 
        46, 42, 50, 36, 29, 32]

def permute(pt, arr, n):
    per = ""
    for i in range(0,n):
        per = per + pt[arr[i]-1]
    return per

def bin2dec(binary): 
        
    binary1 = binary 
    decimal, i, n = 0, 0, 0
    while(binary != 0): 
        dec = binary % 10
        decimal = decimal + dec * pow(2, i) 
        binary = binary//10
        i += 1
    return decimal

def dec2bin(num): 
    res = bin(num).replace("0b", "")
    if(len(res)%4 != 0):
        div = len(res) / 4
        div = int(div)
        counter =(4 * (div + 1)) - len(res) 
        for i in range(0, counter):
            res = '0' + res
    return res

def hexToBin(s):
    mp = {'0' : "0000", 
            '1' : "0001",
            '2' : "0010", 
            '3' : "0011",
            '4' : "0100",
            '5' : "0101", 
            '6' : "0110",
            '7' : "0111", 
            '8' : "1000",
            '9' : "1001", 
            'A' : "1010",
            'B' : "1011", 
            'C' : "1100",
            'D' : "1101", 
            'E' : "1110",
            'F' : "1111" }
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin

def bin2hex(s):
    mp = {"0000" : '0', 
            "0001" : '1',
            "0010" : '2', 
            "0011" : '3',
            "0100" : '4',
            "0101" : '5', 
            "0110" : '6',
            "0111" : '7', 
            "1000" : '8',
            "1001" : '9', 
            "1010" : 'A',
            "1011" : 'B', 
            "1100" : 'C',
            "1101" : 'D', 
            "1110" : 'E',
            "1111" : 'F' }
    hex = ""
    for i in range(0,len(s),4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1] 
        ch = ch + s[i + 2] 
        ch = ch + s[i + 3] 
        hex = hex + mp[ch]
        
    return hex

def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

def Sleft(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1,len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = "" 
    return k

def encrypt(pt, roundKeyBinary, roundKey):
    pt = hexToBin(pt)
    pt = permute(pt, IP, 64)
    print("After inital permutation", bin2hex(pt))
    left = pt[:32]
    right = pt[32:64]
    for i in range(16):
        Rexpanded = permute(right, Dbox, 48)    # Expanding 32 bit data into 48
        x = xor(Rexpanded, roundKeyBinary[i])   # Xorring right expanded and roundKey
        sbox_str = ""
        for j in range(0, 8):
            row = bin2dec(int(x[j * 6] + x[j * 6 + 5]))
            col = bin2dec(int(x[j * 6 + 1] + x[j * 6 + 2] + x[j * 6 + 3] + x[j * 6 + 4]))
            val = Sbox[j][row][col]
            sbox_str = sbox_str + dec2bin(val)
        sbox_str = permute(sbox_str, SP, 32)
        result = xor(left, sbox_str)
        left = result
        if(i != 15):
            left, right = right, left 
        print("Round ", i + 1, " ", bin2hex(left), " ", bin2hex(right), " ", roundKey[i])
    combine = left + right
    cipher_text = permute(combine, FP, 64)
    return cipher_text

def DES(pt, key):
    key = hexToBin(key)
    key = permute(key, PC1, 56)
    left = key[0:28]    
    right = key[28:56]
    rkb = []
    rk  = []
    for i in range(0, 16):
        # Shifting the bits by nth shifts by checking from shift table
        left = Sleft(left, ST[i])
        right = Sleft(right, ST[i])
        
        # Combination of left and right string
        combine_str = left + right
        
        # Compression of key from 56 to 48 bits 
        round_key = permute(combine_str, PC2, 48)
    
        rkb.append(round_key)
        rk.append(bin2hex(round_key))
    
    # print("Encryption")
    cipher_text = bin2hex(encrypt(pt, rkb, rk))
    # print("Cipher Text : ",cipher_text)
    return cipher_text

def hashStringToInt(s):
        hashValue = 0
        p = 31
        mod = 1000000007
        p_pow = 1
        for i in range(len(s)):
            hashValue = (hashValue + (1 + ord(s[i]) - ord('a') * p_pow)) % mod
            p_pow = (p_pow * p) % mod
        return hashValue

def zeroKnowledgeProof(transaction):
        n = 100
        p = 1e9 + 7
        g = 2
        seller_name = transaction['Seller']
        f = open('Users.txt', 'rb')
        users = pickle.load(f)
        f.close()
        for user in users:
            if user.username == seller_name:
                seller = user
                break
        propID = transaction['Property-Id']
        
        if propID in seller.ownershipKey:
            x = seller.ownershipKey[propID]
            y = pow(g, x, p)
        else:
            print("Seller does not own this property")
            return False
        count = 0
        while n > 0:
            r = random.randint(0, p-2)
            h = pow(g, r, p)
            b = random.randint(0,1)
            s = (r + b*x) % (p-1)
            bob = pow(g, s, p)
            alice = (h * pow(y, b, p)) % p
            if bob == alice:
                count += 1
            n -= 1
        if count >= 80:
            return True
        else:
            return False

def makDES(pt, key):
    a = DES(pt[:16], key)
    b = DES(pt[16:32], key)
    c = DES(pt[32:48], key)
    d = DES(pt[48:64], key)
    return a+b+c+d

class Block:
    def __init__(self, data, username, prevHash='0', nonce = 0):
        self.username = username
        self.data = data
        self.jsonData = json.dumps(data)
        self.timestamp = datetime.datetime.now().isoformat()
        self.prevHash = prevHash
        self.nonce = nonce
        self.Hash = self.convertToDES(self.calculateHash().upper())
        
    def as_dict(self):
        return {'     Username': self.username, '        Data': self.data , '     Timestamp':self.timestamp, '    Hash:': self.Hash, '         Previous Hash':self.prevHash }

    def calculateHash(self):
        return hashlib.sha256((self.timestamp + self.prevHash + self.jsonData + str(self.nonce)).encode()).hexdigest()

    def convertToDES(self, pt):
        return makDES(pt, "133457799BBCDFF1")

class Users:
    def __init__(self, username, password):
        self.timestamp = datetime.datetime.now().isoformat()
        self.username = username
        self.password = hashlib.sha256(password.encode()).hexdigest()
        self.blockChain = []
        self.serverPubKey = ''
        self.ownershipKey = {}
        
    def as_dict(self):
        return {'     Username': self.username, '        Timestamp': self.timestamp }

    def createBlock(self, data):
        return Block(data, self.username)
    
    # def zeroKnowledgeProof(transaction):
    #     n = 100
    #     p = 1e9 + 7
    #     g = 2
    #     seller_name = transaction['Seller']
    #     f = open('Users.txt', 'rb')
    #     users = pickle.load(f)
    #     f.close()
    #     for user in users:
    #         if user.username == seller_name:
    #             seller = user
    #             break
    #     propID = transaction['Property-Id']
        
    #     if propID in seller.ownershipKey:
    #         x = seller.ownershipKey[propID]
    #         y = pow(g, x, p)
    #     else:
    #         print("Seller does not own this property")
    #         return False
    #     count = 0
    #     while n > 0:
    #         r = random.randint(0, p-2)
    #         h = pow(g, r, p)
    #         b = random.randint(0,1)
    #         s = (r + b*x) % (p-1)
    #         bob = pow(g, s, p)
    #         alice = (h * pow(y, b, p)) % p
    #         if bob == alice:
    #             count += 1
    #         n -= 1
    #     if count >= 80:
    #         return True
    #     else:
    #         return False


    def verifyBlockChain(self):
        blocks = self.blockChain
        for i in range(1,len(blocks)):
            if blocks[i].prevHash != blocks[i-1].Hash:
                return False
        return True


    def verifyTransaction(self, currentBlock):
        print("in verify of this transaction")
        blocks = self.blockChain
        # print(currentBlock.prevHash)
        # print(blocks[-1].Hash)
        if currentBlock.prevHash == blocks[-1].Hash:
            print("in start")
            transactionn = currentBlock.jsonData
            print(transactionn)
        transaction = json.loads(transactionn) 
        n = 100
        p = 2695139
        g = 2
        seller_name = transaction['Seller']
        print(transaction['Seller'])
        f = open('Users.txt', 'rb')
        users = pickle.load(f)
        f.close()
        for user in users:
            if user.username == seller_name:
                seller = user
                break   
        propID = transaction['Property-ID']
        if propID in seller.ownershipKey:
            x = seller.ownershipKey[propID]
            xx = hashStringToInt(x)
            # print(type(xx))
            y = pow(g, xx, p)
            print('after y')
        else:
            print("Seller does not own this property")
            return False
        count = 0
        while n > 0:
            r = random.randint(0, p-2)
            h = pow(g, r, p)
            b = random.randint(0, 1)
            s = (r + b*xx) % (p-1)
            bob = pow(g, s, p)
            alice = (h * pow(y, b, p)) % p
            if bob == alice:
                count += 1
            n -= 1
        print("Done with ZKP")    
        if count >= 80:
            propID = transaction['Property-ID']
            seller_name = transaction['Seller']
            f = open('Users.txt', 'rb')
            users = pickle.load(f)
            for user in users:
                if user.username == seller_name:
                    seller = user
                    break
            buyer_name = transaction['Buyer']
            for user in users:
                if user.username == buyer_name:
                    buyer = user
                    break
            f.close()
            privateKey = seller.ownershipKey[propID]
            privateKey = makDES(privateKey.upper(), "133457799BBCDFF1")
            # privateKey = convertToDES(privateKey.upper())
            seller.ownershipKey.pop(propID)
            buyer.ownershipKey[propID] = privateKey
            f = open('Users.txt', 'wb')
            pickle.dump(users, f)
            f.close()
            return True
        else:
            return False
        return False

    def verifyPoW(self, block):
        val = hashlib.sha256((block.timestamp + block.prevHash + block.jsonData + str(block.nonce)).encode()).hexdigest()
        finalHash = makDES(val.upper(), "133457799BBCDFF1")
        if finalHash != block.Hash:
            return False
        return True

class Admin:                #Miner
    def __init__(self):
        print("Admin Initiated")
        sock = self.create_socket(('localhost', 5000))
        Thread(target=self.start_threads, args=(sock,)).start()
        if os.stat("BlockChain.txt").st_size == 0:
            f = open('BlockChain.txt', 'wb')
            block = Block("Genesis", 'admin')
            
            pickle.dump([block], f)
            f.close()
        if os.stat("Users.txt").st_size == 0:
            f = open('Users.txt', 'wb')
            ownershipKeys = {}
            ownershipKeys['V-331'] = 'E0313093AD206B375846AEE9ED250F66325506FCB743708A2CB4E8A5C62F40DC'
            ownershipKeys['V-332'] = '906FBC38CA7D49C13EE62A0FA33A08C899568ABCFB11E2F62A0E5BF032E89CBE'
            ownershipKeys['V-330'] = 'F3A050A9D4F7A161A575F5C06EFD135653BB20809CF3318E22B6A3E9CB8C8004'
            ownershipKeys['V-333'] = 'FCC37918055E5E6EEAF966AB5196F32977420EEFE946A1851CA438503E01495F'
            ownershipKeys['V-334'] = 'EF2CC80699B4354551A5A58A79E47E5F6DE94B5803D3AB522B8716C54130A054'
            ownershipKeys['V-335'] = '31102207EDFEE978706A9A382E1A7A3114362719950637D3015595D8C62A9D0B'
            ownershipKeys['V-336'] = '04BB08861105799ED2A5931626AF6E6B7B9E24918022DDD2F70D747423663DF5'
            ownershipKeys['V-337'] = 'BCF9327D9E7ED46C6DF72A8499DBF2F925C6C9BCC234F59F5E75831601FD9BE9'
            ownershipKeys['V-231'] = '38ABA67ECCCC1541E7ADB51FBC9BC045267C42249DC8B3021C23497D009D9F42'
            ownershipKeys['M-251'] = 'BE7627BDED997F08C8E7B36660ED521A2293C31AB9C278A49AC3B7578C9D1B2C'
            user = self.createUser('Genesis', 'admin', ownershipKeys)
            pickle.dump([user], f)
            f.close()

    def createUser(self, username, password):
        print("Inside createUser")
        user = Users(username, password)
        if not os.stat("BlockChain.txt").st_size == 0:
            f = open('BlockChain.txt', 'rb')
            blocks = pickle.load(f)
            f.close()
            user.blockChain = blocks
        # print(user.username, user.password)
        if not os.stat("Users.txt").st_size == 0:
            f = open('Users.txt', 'rb')
            users = pickle.load(f)
            f.close()
            users.append(user)
            f = open('Users.txt', 'wb')
            pickle.dump(users, f)
            f.close()
        return user

    def checkData(self, block):
        f = open('Users.txt','rb')
        users = pickle.load(f)
        f.close()
        transactbool = 0
        hashbool = 0
        for i in range(0,len(users)):
            transact = users[i].verifyTransaction(block)
            hashing = users[i].verifyPoW(block)
            if transact:
                transactbool+=1
            if hashing:
                hashbool+=1
        print(transactbool, hashbool)
        if hashbool > len(users)/2 and transactbool > len(users)/2 :
            return True
        return False

    def addBlock(self, block):
        f = open('BlockChain.txt', 'rb')
        blocks = pickle.load(f)
        f.close()
        blocks.append(block)
        f = open('BlockChain.txt', 'wb')
        pickle.dump(blocks, f)
        f.close()
        f = open('Users.txt', 'rb')
        users = pickle.load(f)
        f.close()
        for i in range(0,len(users)):
            users[i].blockChain = blocks
        f = open('Users.txt', 'wb')
        pickle.dump(users, f)
        f.close()
        return

    def create_socket(self, address):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(address)
        listener.listen(64)
        print('listening at {}'.format(address))
        return listener

    def accept_forever(self, listener):
        while True:
            sock, address = listener.accept()
            print('Accepted connection from {}'.format(address))
            ans = self.authenticate(sock)
            if not ans:
                sock.sendall('Authentication Failed'.encode())
                continue
            self.handle_conversation(sock,address)

    def authenticate(self, sock):
        data = sock.recv(4096)
        username = data.decode()
        print(username)
        f = open('Users.txt', 'rb')
        users = pickle.load(f)
        f.close()
        currUser = ''
        for user in users:
            if user.username == username:
                currUser = username
                break
        if currUser == '':
            sock.sendall('Username not in record'.encode())
            return False
        sock.sendall('Username Received'.encode())

        data = b''
        payload_size = struct.calcsize("L")
        print("Expecting Password")
        while len(data) < payload_size:
            data += sock.recv(4096)
        packed_msg_size = data[:payload_size]
        data = data[payload_size:]
        msg_size = struct.unpack("L", packed_msg_size)[0]
        while len(data) < msg_size:
            data += sock.recv(4096)
        block_data = data[:msg_size]
        data = data[msg_size:]
        password = pickle.loads(block_data)
        rsa = RSA()
        password = rsa.getDecryption(password, prKey[0], prKey[1])

        f = open('Users.txt', 'rb')
        users = pickle.load(f)
        f.close()
        for user in users:
            if user.username == username:
                currUser = user
                break
        hashedPT = hashlib.sha256(password.encode()).hexdigest()
        if not hashedPT == user.password:
            return False
        return True

    def handle_conversation(self, sock, address):
        try:
            val = self.handle_request(sock)
            if not val:
                print("Mining not verified by consensus of the users")
                return
        except EOFError:
            print('Client socket to {} has closed'.format(address))
        except Exception as e:
            print('Client {} error {}'.format(address,e))
        finally:
            sock.close()

    def handle_request(self, sock):
        data = b''
        payload_size = struct.calcsize("L")
        sock.sendall('Send Block'.encode())
        print("Expecting Data")
        while len(data) < payload_size:
            data += sock.recv(4096)
        packed_msg_size = data[:payload_size]
        data = data[payload_size:]
        msg_size = struct.unpack("L", packed_msg_size)[0]
        while len(data) < msg_size:
            data += sock.recv(4096)
        block_data = data[:msg_size]
        data = data[msg_size:]
        block = pickle.loads(block_data)
        self.mineBlock(block)
        toProceed = self.checkData(block)
        if not toProceed:
            return False
        print("PoW done by miner verified by consensus of users")
        self.addBlock(block)
        sock.sendall('Block has been added to the BlockChain'.encode())
        return True

    def mineBlock(self, block, difficulty = 5):
        while block.Hash[:difficulty] != '0'*difficulty:
            block.nonce+=1
            block.Hash = block.calculateHash()
        print(block.nonce, block.Hash)
        finalHash = makDES(block.Hash.upper(), "133457799BBCDFF1")
        block.Hash = finalHash
        return 

    def start_threads(self, listener, workers=4):
        print("here")
        t = (listener,)
        for i in range(workers):
            Thread(target=self.accept_forever, args=t).start()
        return