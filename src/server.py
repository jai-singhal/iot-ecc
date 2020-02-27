from flask import Flask
from flask_api import FlaskAPI, status, exceptions
from flask import request, render_template
from ecc import getCurve, decrypt_ECC, ecc_point_to_256_bit_key, encrypt_ECC
import hashlib, secrets, binascii
import pickle
import base64, requests


app = FlaskAPI(__name__)
secretKey = None
curve = None

data = {}

@app.route('/')
def example():
    return {'hello': 'world'}

@app.route('/globalparam/exchange/', methods=['GET'])
def globalParamsRequest():
    global curve
    deviceInfo = request.args.get("device-id")
    data[deviceInfo] = dict()
    curve = getCurve('brainpoolP256r1')
    data[deviceInfo]["curve"] = curve
    params = {
        "curve":  base64.b64encode(pickle.dumps(curve)).decode("utf-8")
    }
    print(data)
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
    secretKey = ecc_point_to_256_bit_key(aG*privateKey)
    return params


@app.route('/send/msg/', methods=['POST'])
def recieveMessage():
    encryptedmsg = pickle.loads(base64.b64decode(request.data["msg"]))
    decryptedMsg = decrypt_ECC(encryptedmsg, secretKey)
    print("decrypted msg:", decryptedMsg.decode("utf-8"))
    return {"msg": decryptedMsg.decode("utf-8")}


@app.route('/send/plainmsg/', methods=['POST'])
def recievePlainMessage():
    global secretKey
    msg = request.data["msg"].encode('utf-8')
    print("PLain Text msg:", msg.decode("utf-8"))

    encryptedMsg = encrypt_ECC(msg, secretKey)
    encryptedMsgObj = base64.b64encode(pickle.dumps(encryptedMsg)).decode("utf-8")
    return {"msg": encryptedMsgObj}



if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8000,threaded=True)