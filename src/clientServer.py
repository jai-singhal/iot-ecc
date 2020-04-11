
from fastapi import FastAPI, Request, Response, Form, status
from fastapi.responses import JSONResponse
from utils.ecc import *
import hashlib, secrets, binascii
import pickle
import base64, requests
import datetime, json
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from pydantic import BaseModel

portNo = 8000
app = FastAPI()
BASEURL_CLIENT_DYN = None

config = None
db = TinyDB('db/serverdb.json')#, storage=CachingMiddleware(JSONStorage))

with open("./config.json", "r") as f:
    config = json.loads(f.read())
    print(config)

BASEURL_SERVER= config["local"]["server"]["BASEURL_SERVER"]
BASEURL_CLIENT1 = config["local"]["client"]["BASEURL_CLIENT1"]
BASEURL_CLIENT2 = config["local"]["client"]["BASEURL_CLIENT2"]



@app.post('/ecc/post/client/register/')
def getClientGlobalParams(cli:ClientParams):
    try:
        ClientQ = Query()
        print(db.get(ClientQ.deviceid == cli.device_id))

        if db.get(ClientQ.deviceid == cli.device_id) is not None:
            return {"status": True, "message": "Client already registred"}

        print("Register")
        
        db.insert(
            {'deviceid': cli.device_id, 'curve_name': cli.curve_name,
            "latitude": cli.latitude, "longitude": cli.longitude,
            "created_at": str(datetime.datetime.now())
        })
        return {"status": True, "message": "Client registred successfully"}
    except Exception as e:
        return {"status": False, "error": str(e)}



@app.get('/ecc/post/keyexchange/')
def clientRequest(device_id:str, clipubKey:str):

    ClientQ = Query()

    if db.get(ClientQ.deviceid == device_id) is None:
        return {"status": False, "error": "Client not registred"}
    try:
        # Get a
        curve_name = db.get(ClientQ.deviceid == device_id)["curve_name"]
        curve = getCurve(curve_name)
        clientPubKey = pickle.loads(binascii.unhexlify(clipubKey))
    
        # generate private key for server
        privateKey = secrets.randbelow(curve.field.n)
        serverPubKey = privateKey*curve.g
        params = {
            "pubKey":  binascii.hexlify(pickle.dumps(serverPubKey)),
            "status": True
        }

        secretKey = ecc_point_to_256_bit_key(privateKey*clientPubKey)
        db.update(
            {'secretKey': binascii.hexlify(secretKey).decode("utf-8")}, 
            ClientQ.deviceid == device_id
        )
        return params
    except Exception as e:
        return {"status": False, "error": str(e)}

