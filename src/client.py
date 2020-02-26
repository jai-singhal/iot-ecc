from flask import Flask
from flask_api import FlaskAPI, status, exceptions
from flask import request, render_template
import requests
import random
import secrets, binascii
from ecc import getCurve, encrypt_ECC, ecc_point_to_256_bit_key
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
    
    secretKey = ecc_point_to_256_bit_key(bG*privateKey)
    print(secretKey)


def sendMessage():
    msg = "My name is Jai".encode('utf-8')
    encryptedMsg = encrypt_ECC(msg, secretKey)
    encryptedMsgObj = base64.b64encode(pickle.dumps(encryptedMsg)).decode("utf-8")
    response = requests.post(url = "http://127.0.0.1:8000/send/msg/", data={"msg":encryptedMsgObj})
    print(response.status_code)



if __name__ == "__main__":
    knowMyGlobalParams()
    keyExchange()
    sendMessage()
    app.run(host="0.0.0.0",port=5001,threaded=True)