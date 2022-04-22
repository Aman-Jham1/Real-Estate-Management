from Utils import Admin, Block, Users
import socket
import pickle
import struct
import getpass
import pandas as pd
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pubKey = (98581262173360837326167111125113695068362686677036762762847714161386363356381, 5)


if __name__ =='__main__':
    ad = Admin()
    choicesDict = {
        '1':'Create New User',
        '2':'View All Users', 
        '3':'View Current BlockChain',
        '4':'View All Transactions for a User',
        '5':'View Admin\'s Public Key'
    }

    while True:
        # print(choicesDict)
        print('1', choicesDict['1'])
        print('2', choicesDict['2'])
        print('3', choicesDict['3'])
        print('4', choicesDict['4'])
        print('5', choicesDict['5'])
        inp = input("Enter your choice, q to quit: ")
        if inp=='1':
            username = input("\tEnter Username: ")
            f = open('Users.txt', 'rb')
            users = pickle.load(f)
            f.close()
            flag = 0
            for user in users:
                if user.username.lower() == username.lower():
                    print("Username already exists!")
                    flag = 1
                    break
            if flag == 1:
                continue
            password = getpass.getpass(prompt="\tEnter Password: ")
            ad.createUser(username, password)
        elif inp=='2':
            f = open('Users.txt', 'rb')
            users = pickle.load(f)
            df = pd.DataFrame([x.as_dict() for x in users])
            print("\n",df,"\n")
            f.close()
            # for user in users:
            #     print(f'Username: {user.username} , Timestamp: {user.timestamp}')
        elif inp=='3':
            f = open('BlockChain.txt', 'rb')
            blocks = pickle.load(f)
            # df = pd.DataFrame([x.as_dict() for x in blocks])
            # print("\n",df,"\n")
            f.close()
            for block in blocks:
                print(f'{block.username} , {block.data} , {block.timestamp} , {block.Hash} , {block.prevHash}')
                # pr = {}
                # pr['username'] = block.username
                # pr['data'] = block.data
                # pr['timestamp'] = block.timestamp
                # pr['Hash'] = block.Hash
                # pr['prevHash'] = block.prevHash
                # print(repr(pr))
        elif inp=='4':
            u = input("\tEnter Username: ")
            f = open('Users.txt', 'rb')
            users = pickle.load(f)
            f.close()
            currUser = ''
            for user in users:
                if user.username == u:
                    currUser = user
                    break
            if currUser == '':
                print("No such User exists!")
                continue
            print("User Transactions are as follows: ")
            f = open('BlockChain.txt', 'rb')
            blocks = pickle.load(f)
            f.close()
            transaction = []
            for block in blocks:
                if block.username == u:
                    transaction.append(block.data)
            if len(transaction) == 0:
                print("The user has indulged in no transactions yet!")
                continue
            # print(repr(transaction))
            for i in transaction:
                print("\t",i)
        elif inp=='5':
            print(f'Public Key is: {pubKey}')
        elif inp=='q':
            break
    exit(0)

