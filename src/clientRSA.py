import requests

import binascii
import base64
import time
import json
import binascii
import rsa
import os

clientData = {
    "device_id": 1,
    "server_public": None,
    "transaction_id": None,
    "key_size": None
}
'''
CURR_CLIENT_BASEURL = None

config = None
with open("./config.json", "r") as f:
    config = json.loads(f.read())

BASEURL_SERVER = config["local"]["server"]["BASEURL_SERVER"]
BASEURL_CLIENT1 = config["local"]["client"]["BASEURL_CLIENT1"]
BASEURL_CLIENT2 = config["local"]["client"]["BASEURL_CLIENT2"]
'''
BASEURL_SERVER = "http://localhost:8090"
MSG_FOLDER = "msg_folder"

"""
/rsa/get/keyexchange
/rsa/post/msg
/rsa/send/time/encrypt
/rsa/performance
"""

def keyExchange(key_size):
    data = {
        "device_id": clientData["device_id"],
        "key_size": key_size
    }

    response = requests.get(
        url = BASEURL_SERVER + "/rsa/get/keyexchange", 
        params=data
    )
    response = response.json()
    if not response["public"]:
        print(response["error"])
        return False

    print("---------------------")
    clientData["transaction_id"] = (response["transaction_id"])
    serverPubKey = (response["public"])
    tmp = rsa.PublicKey
    serverPubKey = tmp.load_pkcs1(serverPubKey)
    clientData["server_public"] = serverPubKey
    print(clientData)
    return True


def sendMessageStepwise(msg):
    data = {
        "device_id": clientData["device_id"],
        "transaction_id": clientData["transaction_id"]
    }
    total_time=0.0
    #complete_msg_encrypted=[]
    total_subtract=0.0
    max_bytes_msg=clientData["key_size"]//8-11

    for msg_ind in range(0,len(msg),max_bytes_msg):
        mod_msg=msg[msg_ind:msg_ind+max_bytes_msg]
        start=float(time.process_time_ns())
        bytemsg=rsa.encrypt(mod_msg.encode('utf-8'),clientData["server_public"])
        rtnmsg=binascii.hexlify(bytemsg)
        encryptedMsgObj=rtnmsg.decode('utf-8')
        #complete_msg_encrypted.append(encryptedMsgObj)
    #complete_msg_encrypted=''.join(complete_msg_encrypted)
        start_sub=float(time.process_time_ns())
        response = requests.post(
                url = BASEURL_SERVER + "/rsa/post/stepwise/msg", 
                params = data,
                data = {
                    "msg":encryptedMsgObj#complete_msg_encrypted
                }
            )
        end_sub=float(time.process_time_ns())
        end=float(time.process_time_ns())
        total_time+=end-start
        total_subtract+=end_sub-start_sub
    if response.status_code == 200:
        data = {
            "transaction_id": clientData["transaction_id"],
            "encrypt_time":total_time-total_subtract
        }
        response = requests.get(
            url = BASEURL_SERVER + "/rsa/send/time/encrypt", 
            params=data
        )
        if response.status_code == 200:
            return True
        return False
    else:
        return False

def sendMessage(msg):
    data = {
        "device_id": clientData["device_id"],
        "transaction_id": clientData["transaction_id"]
    }
    total_time=0.0
    complete_msg_encrypted=[]
    max_bytes_msg=clientData["key_size"]//8-11

    start=float(time.process_time_ns())
    for msg_ind in range(0,len(msg),max_bytes_msg):
        mod_msg=msg[msg_ind:msg_ind+max_bytes_msg]
        bytemsg=rsa.encrypt(mod_msg.encode('utf-8'),clientData["server_public"])
        rtnmsg=binascii.hexlify(bytemsg)
        encryptedMsgObj=rtnmsg.decode('utf-8')
        complete_msg_encrypted.append(encryptedMsgObj)
    end=float(time.process_time_ns())
    complete_msg_encrypted=''.join(complete_msg_encrypted)
    response = requests.post(
        url = BASEURL_SERVER + "/rsa/post/big/msg", 
        params = data,
        data = {
            "msg":complete_msg_encrypted#complete_msg_encrypted
        }
    )
    total_time=end-start
    if response.status_code == 200:
        data = {
            "transaction_id": clientData["transaction_id"],
            "encrypt_time":total_time
        }
        response = requests.get(
            url = BASEURL_SERVER + "/rsa/send/time/encrypt", 
            params=data
        )
        if response.status_code == 200:
            return True
        return False
    else:
        return False

def iter_inner(key_size,msg):
    clientData["key_size"]=key_size
    keyExchange(key_size)
    res = sendMessage(msg)
    clientData['device_id']+=1

def iter(key_size,msg_folder,iterations_per_file):
    files=os.listdir(msg_folder)
    for f in files:
        with open(msg_folder+"/"+f, 'r') as file:
            msg=file.read()
            for i in range(iterations_per_file):
                iter_inner(128,msg)

if __name__ == "__main__":
    iter(128,MSG_FOLDER,10)
    print("done")
