from fastapi import FastAPI, Request, Response, Form, status, File, UploadFile
from fastapi.responses import JSONResponse
from utils import ecc
import hashlib, secrets, binascii
import pickle
import base64, requests
import datetime
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from pydantic import BaseModel
import rsa
import time
from timeit import default_timer as timer

app = FastAPI()


@app.get('/')
def example():
    return {'hello': 'world'}

class ClientParams(BaseModel):
    device_id: str
    latitude: str = None
    longitude: str = None
    curve_name: str = None
    latitude: str = None
    curve: str = None
    secretKey: str = None

class ClientReq(BaseModel):
    device_id: str

@app.post('/ecc/attestation/client/register/')
def ecc_getClientGlobalParams(cli:ClientParams):
    try:
        ClientQ = Query()
        # print(dbECC.get(ClientQ.deviceid == cli.device_id))
        if dbECC.get(ClientQ.deviceid == cli.device_id) is not None:
            return {"status": True, "message": "Client already registred"}
        
        dbECC.insert(
            {'deviceid': cli.device_id, 'curve_name': cli.curve_name,
            "latitude": cli.latitude, "longitude": cli.longitude,
            "created_at": str(datetime.datetime.now())
        })
        return {"status": True, "message": "Client registred successfully"}
    except Exception as e:
        print(e)
        return {"status": False, "error": str(e)}


@app.post('/ecc/attestation/keyexchange/')
def ecc_clientRequest(
    device_id:str=Form(...), 
    clipubKey:str=Form(...),
    clikeygentime:float=Form(...),
):
    ClientQ = Query()

    if dbECC.get(ClientQ.deviceid == device_id) is None:
        return {"status": False, "error": "Client not registred"}
    try:
        total_time = 0
        # Get a
        curve_name = dbECC.get(ClientQ.deviceid == device_id)["curve_name"]

        curve = ecc.getCurve(curve_name)
        clientPubKey = pickle.loads(binascii.unhexlify(clipubKey))

        tick = timer()
        # generate private key for server
        privateKey = secrets.randbelow(curve.field.n)
        serverPubKey = privateKey*curve.g
        tock = timer()
        total_time += (tock-tick)*(10**9)
        tick = timer()
        secretKey = ecc.ecc_point_to_256_bit_key(privateKey*clientPubKey)
        tock = timer()
        total_time += 2*(tock-tick)*(10**9) # 2time key gen
        total_time += clikeygentime

        dbECC.update({
                'secretKey': binascii.hexlify(secretKey).decode("utf-8"),
                'keygen_time': total_time
            }, 
            ClientQ.deviceid == device_id
        )
        return {
            "pubKey":  binascii.hexlify(pickle.dumps(serverPubKey)),
            "status": True
        }
    except Exception as e:
        print(e)
        return {"status": False, "error": str(e)}


@app.post('/ecc/attestation/send/msg/')
def ecc_recieveMessage(
    encryptedMsg:str=Form(...), 
    filepath:str=Form(...), 
    device_id:str=Form(...),
    encr_time:float=Form(...),
    keysize:int=Form(...),
):
    ClientQ = Query()
    secretKey = dbECC.get(ClientQ.deviceid == device_id)["secretKey"]

    tick = timer()
    tag, nonce, ct = encryptedMsg[0:32], encryptedMsg[32:64], encryptedMsg[64:]
    ct = binascii.unhexlify(ct)
    tag = binascii.unhexlify(tag)
    nonce = binascii.unhexlify(nonce)
    decryptedMsg = ecc.decrypt_AES_GCM(ct, nonce, tag, binascii.unhexlify(secretKey.encode("utf-8")))
    tock = timer()
    decryptedMsg = decryptedMsg.decode("utf-8")
    # print("decrypted msg:", decryptedMsg)
    decr_time = (tock-tick)*(10**9)
    print("Encrypt time", encr_time)
    print("Decrypt time", decr_time)

    msg_len = len(decryptedMsg)/1000

    dbECCData.insert({
        "transaction_id": len(dbECCData),
        "encrypt_time": encr_time,
        "decrypt_time": decr_time,
        "total_time": encr_time+decr_time,
        # "message": decryptedMsg,
        "filepath": filepath,
        "msg_len": msg_len,
        "keysize": keysize
    })
    return {"msg": decryptedMsg}
