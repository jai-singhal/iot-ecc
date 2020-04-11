import requests

import secrets, binascii
import base64
import time
import json
import binascii
import rsa

clientData = {
    "device_id": 1,
    "server_public": None
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

def keyExchange():
    data = {
        "device_id": clientData["device_id"]
    }

    response = requests.get(
        url = BASEURL_SERVER + "/globalparam/exchange/rsa", 
        params=data
    )
    response = response.json()
    if not response["status"]:
        print(response["error"])
        return False

    print("---------------------")

    serverPubKey = (response["public"])
    tmp = rsa.PublicKey
    serverPubKey = tmp.load_pkcs1(serverPubKey)
    clientData["server_public"] = serverPubKey
    print(clientData)
    return True


def sendMessage(msg):
    data = {
        "device_id": clientData["device_id"]
    }
    bytemsg=rsa.encrypt(msgstr.encode('utf-8'),clientData["server_public"])
    rtnmsg=binascii.hexlify(bytemsg)
    encryptedMsgObj=rtnmsg.decode('utf-8')
    response = requests.post(
        url = BASEURL_SERVER + "/send/msg/rsa", 
        params = data,
        data = {"msg":encryptedMsgObj}
    )
    if response.status_code == 200:
        return True
    else:
        return False


if __name__ == "__main__":

    print("Retrieveing public key value from server")
    keyExchange()

    print("Done!!")
    print("--"*20 + "\n")

    print("Let's send the message")
    
    while True:
        msg = input("Enter the message to send: ")
        if(msg == "exit"):
            break
        res = sendMessage(msg)
        if res:
            print("Message sent successfully")
    