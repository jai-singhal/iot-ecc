from flask import Flask
from flask_api import FlaskAPI, status, exceptions
from flask import request, render_template
from ecc import getCurve, decrypt_ECC
import hashlib, secrets, binascii
import pickle
import base64, requests


app = FlaskAPI(__name__)
secretKey = None
curve = None


@app.route('/globalparam/exchange/', methods=['GET'])
def globalParamsRequest():
    global curve
    curve = getCurve('brainpoolP256r1')
    params = {
        "curve":  base64.b64encode(pickle.dumps(curve)).decode("utf-8")
    }
    return params


@app.route('/keyexchange/', methods=['POST'])
def clientRequest():
    global secretKey
    # Get a
    aG = pickle.loads(base64.b64decode(request.data["pr"]))

    # generate b
    privateKey = secrets.randbelow(curve.field.n)
    bG = privateKey*curve.g

    params = {
        "pr":  base64.b64encode(pickle.dumps(bG)).decode("utf-8")
    }
    secretKey = privateKey
    return params


@app.route('/send/msg/', methods=['POST'])
def getMessage():
    encryptedmsg = pickle.loads(base64.b64decode(request.data["msg"]))
    print(encryptedmsg)
    decryptedMsg = decrypt_ECC(encryptedmsg, secretKey)
    print("decrypted msg:", decryptedMsg)
    return {}



if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8000,threaded=True)