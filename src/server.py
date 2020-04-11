from fastapi import FastAPI, Request, Response, Form, status
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

app = FastAPI()
# https://pypi.org/project/tinydb/
db = TinyDB('db/serverdb.json')#, storage=CachingMiddleware(JSONStorage))

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

@app.post('/ecc/post/client/register/')
def getClientGlobalParams(cli:ClientParams):
    try:
        ClientQ = Query()
        print(db.get(ClientQ.deviceid == cli.device_id))

        if db.get(ClientQ.deviceid == cli.device_id) is not None:
            return {"status": True, "message": "Client already registred"}
        
        db.insert(
            {'deviceid': cli.device_id, 'curve_name': cli.curve_name,
            "latitude": cli.latitude, "longitude": cli.longitude,
            "created_at": str(datetime.datetime.now())
        })
        return {"status": True, "message": "Client registred successfully"}
    except Exception as e:
        print(e)
        return {"status": False, "error": str(e)}


@app.post('/ecc/post/keyexchange/')
def clientRequest(device_id:str=Form(...), clipubKey:str=Form(...)):
    ClientQ = Query()

    if db.get(ClientQ.deviceid == device_id) is None:
        return {"status": False, "error": "Client not registred"}
    try:
        # Get a
        curve_name = db.get(ClientQ.deviceid == device_id)["curve_name"]
        curve = ecc.getCurve(curve_name)
        clientPubKey = pickle.loads(binascii.unhexlify(clipubKey))
    
        # generate private key for server
        privateKey = secrets.randbelow(curve.field.n)
        serverPubKey = privateKey*curve.g
        params = {
            "pubKey":  binascii.hexlify(pickle.dumps(serverPubKey)),
            "status": True
        }

        secretKey = ecc.ecc_point_to_256_bit_key(privateKey*clientPubKey)
        db.update(
            {'secretKey': binascii.hexlify(secretKey).decode("utf-8")}, 
            ClientQ.deviceid == device_id
        )
        return params
    except Exception as e:
        print(e)
        return {"status": False, "error": str(e)}


@app.post('/ecc/send/msg/')
def recieveMessage(encryptedMsg:str=Form(...), device_id:str=Form(...)):
    ClientQ = Query()
    tag, nonce, ct = encryptedMsg[0:32], encryptedMsg[32:64], encryptedMsg[64:]
    ct = binascii.unhexlify(ct)
    tag = binascii.unhexlify(tag)
    nonce = binascii.unhexlify(nonce)
    secretKey = db.get(ClientQ.deviceid == device_id)["secretKey"]
    decryptedMsg = ecc.decrypt_AES_GCM(ct, nonce, tag, binascii.unhexlify(secretKey.encode("utf-8")))
    print("decrypted msg:", decryptedMsg.decode("utf-8"))
    return {"msg": "decryptedMsg"}

