import requests
import binascii
import base64
import time
import json
import binascii
import rsa
import os
from timeit import default_timer as timer
from tqdm import tqdm


def clearDB():
    # with open("../../db/serverdbECC.json", "w") as fout:
    #     fout.write("")
    with open("../../db/serverdbRSA.json", "w") as fout:
        fout.write("")

clearDB()

with open("../../config/config.json", "r") as f:
    config = json.loads(f.read())

BASEURL_SERVER = config["local"]["server"]["BASEURL_SERVER"]
MSG_FOLDER = config["local"]["client"]["MSG_FOLDER_CLIENT1"]
KEY_SIZE = config["local"]["client"]["RSA_KEY_SIZE_CLIENT1"]
ITERATIONS_PER_FILE = config["local"]["client"]["RSA_ITERATIONS_PER_FILE_CLIENT1"]

"""
/rsa/get/keyexchange
/rsa/post/msg
/rsa/send/time/encrypt
/rsa/performance
"""
class ClientRSA():
    def __init__(self, CURR_CLIENT_BASEURL, BASEURL_SERVER):
        self.clientData = {}
        self.CURR_CLIENT_BASEURL = CURR_CLIENT_BASEURL
        self.BASEURL_SERVER = BASEURL_SERVER
        self.fillClientData()

    def fillClientData(self):
        self.clientData["device_id"] = 1
        self.clientData["server_public"] = None
        self.clientData["transaction_id"] = None
        self.clientData["key_size"] = None

    def prebuiltkey_transactionid(self):
        data = {
            "device_id": self.clientData["device_id"]
        }
        response = requests.get(
            url = self.BASEURL_SERVER + "/rsa/prebuiltkeys/timer", 
            params=data
        )
        response = response.json()
        if not response["transaction_id"]:
            print(response["error"])
            return False

        self.clientData["transaction_id"] = (response["transaction_id"])
        return True

    def keyExchange(self,key_size):
        data = {
            "device_id": self.clientData["device_id"],
            "key_size": key_size
        }
        response = requests.get(
            url = self.BASEURL_SERVER + "/rsa/get/keyexchange", 
            params=data
        )
        response = response.json()
        if not response["public"]:
            print(response["error"])
            return False

        self.clientData["transaction_id"] = (response["transaction_id"])
        serverPubKey = (response["public"])
        tmp = rsa.PublicKey
        serverPubKey = tmp.load_pkcs1(serverPubKey)
        self.clientData["server_public"] = serverPubKey
        return True


    def sendMessageStepwise(self,msg):
        data = {
            "device_id": self.clientData["device_id"],
            "transaction_id": self.clientData["transaction_id"]
        }
        total_time=0.0
        #complete_msg_encrypted=[]
        total_subtract=0.0
        max_bytes_msg=self.clientData["key_size"]//8-11

        for msg_ind in tqdm(range(0,len(msg),max_bytes_msg),desc="encrypting msg ["+str(self.clientData["transaction_id"])+"]"):
            mod_msg=msg[msg_ind:msg_ind+max_bytes_msg]
            start=timer()*(10**3)
            bytemsg=rsa.encrypt(mod_msg.encode('utf-8'),self.clientData["server_public"])
            rtnmsg=binascii.hexlify(bytemsg)
            encryptedMsgObj=rtnmsg.decode('utf-8')
            #complete_msg_encrypted.append(encryptedMsgObj)
        #complete_msg_encrypted=''.join(complete_msg_encrypted)
            start_sub=timer()*(10**3)
            response = requests.post(
                    url = self.BASEURL_SERVER + "/rsa/post/stepwise/msg", 
                    params = data,
                    data = {
                        "msg":encryptedMsgObj
                    }
                )
            end_sub=timer()*(10**3)
            end=timer()*(10**3)
            total_time+=end-start
            total_subtract+=end_sub-start_sub
        if response.status_code == 200:
            data = {
                "transaction_id": self.clientData["transaction_id"],
                "encrypt_time":total_time-total_subtract
            }
            response = requests.get(
                url = self.BASEURL_SERVER + "/rsa/send/time/encrypt", 
                params=data
            )
            if response.status_code == 200:
                return True
            return False
        else:
            return False

    def sendMessage(self,msg):
        prm = {
            "device_id": self.clientData["device_id"],
            "transaction_id": self.clientData["transaction_id"]
        }
        total_time=0.0
        complete_msg_encrypted=[]
        max_bytes_msg=self.clientData["key_size"]//8-11

        start=timer()*(10**3)
        for msg_ind in tqdm(range(0,len(msg),max_bytes_msg),desc="encrypting msg ["+str(self.clientData["transaction_id"])+"]"):
            mod_msg=msg[msg_ind:msg_ind+max_bytes_msg]
            bytemsg=rsa.encrypt(mod_msg.encode('utf-8'),self.clientData["server_public"])
            rtnmsg=binascii.hexlify(bytemsg)
            encryptedMsgObj=rtnmsg.decode('utf-8')
            complete_msg_encrypted.append(encryptedMsgObj)
        end=timer()*(10**3)
        complete_msg_encrypted=''.join(complete_msg_encrypted)
        print("done encrypting sending msg to server")
        
        data = {
            "msg":complete_msg_encrypted
        }
        response = requests.post(
            url = self.BASEURL_SERVER + "/rsa/post/big/msg", 
            data = data,
            params = prm
        )
        total_time=end-start
        if response.status_code == 200:
            data = {
                "transaction_id": self.clientData["transaction_id"],
                "encrypt_time":total_time
            }
            response = requests.get(
                url = self.BASEURL_SERVER + "/rsa/send/time/encrypt", 
                params=data
            )
            if response.status_code == 200:
                return True
            return False
        else:
            return False

def iter_inner(cli,key_size,msg):
    cli.clientData["key_size"]=key_size
    res = cli.sendMessage(msg)

def iter(key_size,msg_folder,iterations_per_file):
    global BASEURL_SERVER
    cli=ClientRSA("",BASEURL_SERVER)
    files=os.listdir(msg_folder)
    for i in range(iterations_per_file):
        first_in_iter=True
        for f in files:
            with open(msg_folder+"/"+f, 'r') as file:
                msg=file.read()
                print("running iter ["+str(i)+"] on file ["+str(f)+"]")
                if(first_in_iter):
                    print("performing key exchange")
                    cli.keyExchange(key_size)
                    first_in_iter=False
                else:
                    cli.prebuiltkey_transactionid()
                iter_inner(cli,key_size,msg)
        cli.clientData['device_id']+=1

if __name__ == "__main__":
    iter(KEY_SIZE,MSG_FOLDER,ITERATIONS_PER_FILE)
    print("done iterating :)")
