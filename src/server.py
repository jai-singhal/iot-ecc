from fastapi import FastAPI, Request, Response, Form
from ecc import getCurve, decrypt_ECC, ecc_point_to_256_bit_key, encrypt_ECC
import hashlib, secrets, binascii
import pickle
import base64, requests


app = FastAPI()
secretKey = None
curve = None

data = {}

@app.get('/')
def example():
    return {'hello': 'world'}

@app.get('/globalparam/exchange/')
def globalParamsRequest(device_id, latitude, longitude):
    global curve
    data[device_id] = dict()
    curve = getCurve('brainpoolP256r1')
    data[device_id]["curve"] = curve
    params = {
        "curve":  base64.b64encode(pickle.dumps(curve)).decode("utf-8")
    }
    return params


@app.post('/keyexchange/')
def clientRequest(pr:str=Form(...)):
    global secretKey
    # Get a
    aG = pickle.loads(base64.b64decode(pr))
    # generate b
    privateKey = secrets.randbelow(curve.field.n)
    bG = privateKey*curve.g
    params = {
        "pr":  base64.b64encode(pickle.dumps(bG)).decode("utf-8")
    }
    secretKey = ecc_point_to_256_bit_key(aG*privateKey)
    return params


@app.post('/send/msg/')
def recieveMessage(msg:str=Form(...)):
    encryptedmsg = pickle.loads(base64.b64decode(msg))
    decryptedMsg = decrypt_ECC(encryptedmsg, secretKey)
    print("decrypted msg:", decryptedMsg.decode("utf-8"))
    return {"msg": decryptedMsg.decode("utf-8")}


@app.post('/send/plainmsg/')
def recievePlainMessage(msg:str=Form(...)):
    global secretKey
    msg = msg.encode('utf-8')
    print("PLain Text msg:", msg.decode("utf-8"))
    encryptedMsg = encrypt_ECC(msg, secretKey)
    encryptedMsgObj = base64.b64encode(pickle.dumps(encryptedMsg)).decode("utf-8")
    return {"msg": encryptedMsgObj}



# if __name__ == "__main__":
#     app.run(host="0.0.0.0",port=8000,threaded=True)