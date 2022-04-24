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
            f.close()
            for user in users:
                if user.username == 'Genesis':
                    currUser = user
                    break
            currUser.ownershipKey['V-330'] = 'F3A050A9D4F7A161A575F5C06EFD135653BB20809CF3318E22B6A3E9CB8C8004'
            currUser.ownershipKey['V-331'] = 'E0313093AD206B375846AEE9ED250F66325506FCB743708A2CB4E8A5C62F40DC'
            currUser.ownershipKey['V-332'] = '906FBC38CA7D49C13EE62A0FA33A08C899568ABCFB11E2F62A0E5BF032E89CBE'
            currUser.ownershipKey['V-333'] = 'FCC37918055E5E6EEAF966AB5196F32977420EEFE946A1851CA438503E01495F'
            currUser.ownershipKey['V-334'] = 'EF2CC80699B4354551A5A58A79E47E5F6DE94B5803D3AB522B8716C54130A054'
            currUser.ownershipKey['V-335'] = '31102207EDFEE978706A9A382E1A7A3114362719950637D3015595D8C62A9D0B'
            currUser.ownershipKey['V-336'] = '04BB08861105799ED2A5931626AF6E6B7B9E24918022DDD2F70D747423663DF5'
            currUser.ownershipKey['V-337'] = 'BCF9327D9E7ED46C6DF72A8499DBF2F925C6C9BCC234F59F5E75831601FD9BE9'
            currUser.ownershipKey['V-231'] = '38ABA67ECCCC1541E7ADB51FBC9BC045267C42249DC8B3021C23497D009D9F42'
            currUser.ownershipKey['M-'] = 'BE7627BDED997F08C8E7B36660ED521A2293C31AB9C278A49AC3B7578C9D1B2C'
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

