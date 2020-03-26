
from fastapi import FastAPI, Request, Response, Form

from ecc import getCurve, encrypt_ECC, ecc_point_to_256_bit_key
from ecc import  decrypt_ECC, encrypt_ECC
import pickle
import base64
import time
import random
import uuid
import json
import secrets
import os

portNo = 8000
# if len(sys.argv) == 2:
#     portNo = sys.argv[1]

app = FastAPI()

## Server Code

secretKey = None
curve = None
BASEURL_CLIENT_DYN = None

BASEURL_SERVER= "http://023b8bc8.ngrok.io"
BASEURL_CLIENT1 = "http://127.0.0.1:8001"
BASEURL_CLIENT2 = "http://127.0.0.1:8002"

# if(len(sys.argv)>2 and str(sys.argv[2])=="2"):
#     BASEURL_CLIENT_DYN=BASEURL_CLIENT2
# else:
#     BASEURL_CLIENT_DYN=BASEURL_CLIENT1

@app.post('/send/msg/')
def recieveMessage(msg:str=Form(...)):
    encryptedmsg = pickle.loads(base64.b64decode(msg))

    decryptedMsg = decrypt_ECC(encryptedmsg, secretKey)
    print("decrypted msg:", decryptedMsg.decode("utf-8"))
    return {"msg": decryptedMsg.decode("utf-8")}


@app.post('/keyexchange/')
def clientRequestKeyExchange(pr:str=Form(...), clientid:str=Form(...)):
    global secretKey
    global curve
    #print("Called")
    if(os.path.isfile("./secrets.json")):
        with open(f"./{clientid[-1]}_secrets.json", "r") as f:
            secrets_ = json.loads(f.read())
            curve = pickle.loads(base64.b64decode(secrets_["curve"]))
    else:
        print("./secrets.json file does not exist")
    #print("Calledxx")
    
    # # Get a
    aG = pickle.loads(base64.b64decode(pr))
    # generate b
    privateKey = secrets.randbelow(curve.field.n)
    bG = privateKey*curve.g
    params = {
        "pr":  base64.b64encode(pickle.dumps(bG)).decode("utf-8")
    }
    secretKey = ecc_point_to_256_bit_key(aG*privateKey)
    return params