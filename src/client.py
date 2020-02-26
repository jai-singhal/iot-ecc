from flask import Flask
from flask_api import FlaskAPI, status, exceptions
from flask import request, render_template
import requests
import random
import secrets, binascii
from ecc import getCurve, encrypt_ECC
import pickle
import base64

app = Flask(__name__)
curve = None
secretKey = None


def hello_world():
    return render_template('index.html', context = {})


def knowMyGlobalParams():
    global curve
    response = requests.get(url = "http://127.0.0.1:8000//globalparam/exchange/")
    curve = pickle.loads(base64.b64decode(response.json()["curve"]))


@app.route('/keyexchange/', methods=['POST'])
def keyExchange():
    global secretKey
    # generate a
    privateKey = secrets.randbelow(curve.field.n)
    aG = privateKey*curve.g
    params = {
        "pr":  base64.b64encode(pickle.dumps(aG))
    }
    response = requests.post(url = "http://127.0.0.1:8000/keyexchange/", data=params)
    # print(response.json())
    bG = pickle.loads(base64.b64decode(response.json()["pr"]))
    
    secretKey = bG*privateKey
    print(secretKey)


def sendMessage():
    msg = b"My name is Jai"
    encryptedMsg = encrypt_ECC(msg, secretKey, curve)
    # encryptedMsgObj = {
    #     'ciphertext': binascii.hexlify(encryptedMsg[0]),
    #     'nonce': binascii.hexlify(encryptedMsg[1]),
    #     'authTag': binascii.hexlify(encryptedMsg[2]),
    #     'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
    # }
    print(encryptedMsg)
    encryptedMsgObj = base64.b64encode(pickle.dumps(encryptedMsg)).decode("utf-8")
    response = requests.post(url = "http://127.0.0.1:8000/send/msg/", data={"msg":encryptedMsgObj})

    print(response)



if __name__ == "__main__":
    knowMyGlobalParams()
    keyExchange()
    sendMessage()
    app.run(host="0.0.0.0",port=5001,threaded=True)