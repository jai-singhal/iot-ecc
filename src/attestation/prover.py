from fastapi import FastAPI, Request, Response, Form, status
from fastapi.responses import JSONResponse
from utils import ecc
import hashlib, secrets, binascii
import pickle
import base64, requests
import datetime
import time, json
from timeit import default_timer as timer
import os, sys
import math
import logging

logging.basicConfig(
    format='%(asctime)s - %(message)s', 
    datefmt='%d-%b-%y %H:%M:%S', 
    level=logging.INFO,
    filename="prover.log"
)

CONFIGPATH = "../../config/config.json"

if not os.path.exists(CONFIGPATH):
    logging.error("CONFIG FILE NOT FOUND!!")
    sys.exit(-1)

with open(CONFIGPATH, "r") as f:
    config = json.loads(f.read())

if config["production"] == True:
    pd = "local"
else:
    pd = "development"

BASEURL_SERVER= config[pd]["server"]["BASEURL_SERVER"]
BLOCK_SIZE= config[pd]["server"]["BLOCK_SIZE"]
WORD_SIZE= config[pd]["server"]["WORD_SIZE"]
MEMORY_FILEPATH = config[pd]["server"]["MEMORY_FILEPATH"]
BASEURL_CLIENT1 = config[pd]["client"]["BASEURL_CLIENT1"]

app = FastAPI()

proverParams = {
    "device_id": None,
    "NUM_OF_BLOCKS":0,
    "memoryBlocks": [],
    "secretKey":None,
    "curve": None
}

@app.post('/ecc/attestation/client/register/')
def ecc_getClientGlobalParams(device_id:str=Form(...), curve_name:str=Form(...)):
    global proverParams

    def readMemory(filepath):
        if not os.path.exists(filepath):
            logging.error("No file found")
            return {"status": False, "message": "Memory file not found!!"}

        with open(filepath, "r") as fin:
            fcontent = fin.read()
            NUM_OF_BLOCKS = math.ceil(len(fcontent)/BLOCK_SIZE)
            memoryBlocks = [
                fcontent[i:i+BLOCK_SIZE] 
                for i in range(0, len(fcontent), BLOCK_SIZE)
            ]
            return memoryBlocks

    proverParams["curve"] = ecc.getCurve(curve_name)
    proverParams["device_id"] = device_id
    proverParams["memoryBlocks"] = readMemory(MEMORY_FILEPATH)
    return {"status": True, "message": "Client registred successfully"}


@app.post('/ecc/attestation/keyexchange/')
def ecc_clientRequest(
    device_id:str=Form(...), 
    clipubKey:str=Form(...),
    clikeygentime:float=Form(...),
):
    global proverParams

    try:
        total_time = 0
        # Get a
        curve = proverParams["curve"]
        clientPubKey = pickle.loads(binascii.unhexlify(clipubKey))

        tick = timer()
        # generate private key for server
        privateKey = secrets.randbelow(curve.field.n)
        serverPubKey = privateKey*curve.g
        tock = timer()
        total_time += (tock-tick)*(10**3)
        tick = timer()
        proverParams["secretKey"] = ecc.ecc_point_to_256_bit_key(privateKey*clientPubKey)
        tock = timer()
        total_time += 2*(tock-tick)*(10**3) # 2time key gen
        total_time += clikeygentime

        return {
            "pubKey":  binascii.hexlify(pickle.dumps(serverPubKey)),
            "status": True
        }
    except Exception as e:
        logging.error(e)
        return {"status": False, "error": str(e)}


@app.post('/ecc/attestation/send/msg/')
def ecc_recieveMessage(
    encryptedMsg:str=Form(...), 
    device_id:str=Form(...),
    encr_time:float=Form(...),
    keysize:int=Form(...),
):
    global proverParams
    
    def decryption():
        tag, nonce, ct = encryptedMsg[0:32], encryptedMsg[32:64], encryptedMsg[64:]
        ct = binascii.unhexlify(ct)
        tag = binascii.unhexlify(tag)
        nonce = binascii.unhexlify(nonce)
        decryptedMsg = ecc.decrypt_AES_GCM(ct, nonce, tag, proverParams["secretKey"])
        decryptedMsg = decryptedMsg.decode("utf-8")
        return decryptedMsg

    def encryption(sigma):
        ct, nonce, tag = ecc.encrypt_AES_GCM(
            sigma.encode('utf-8'), 
            proverParams["secretKey"]
        )
        ct = binascii.hexlify(ct).decode("utf-8")
        tag = binascii.hexlify(tag).decode("utf-8")
        nonce = binascii.hexlify(nonce).decode("utf-8")
        cryptogram = tag + nonce + ct
        return cryptogram

    def sigmaGeneration():
        sib, siw = int(tmp[0]), int(tmp[1])
        memoryBlocks = proverParams["memoryBlocks"]
        boi=memoryBlocks[sib]
        sigma=ecc.create_sha256_hash(str(boi))
        return sigma
    
    attest_timer_start=timer()
    try:
        decryptedMsg = decryption()
    except Exception as e:
        logging.error(e)
        return {"status": False, "error": "Decryption problem"}

    tmp = decryptedMsg.split(",")
    if(len(tmp)!=2):
        logging.error("unexpected message sent, send sib and siw")
        return {"status": False, "error": "Invalid sigma"}

    try:
        sigma = sigmaGeneration()
    except Exception as e:
        logging.error(e)
        return {"status": False, "error": "Sigma generation problem"}
    
    try:
        cryptogram = encryption(sigma)
    except Exception as e:
        logging.error(e)
        return {"status": False, "error": "Encryption problem"}
    
    attest_timer_end=timer()
    return {"msg": cryptogram,
            "status": True,
            "prover-time": attest_timer_end-attest_timer_start}
