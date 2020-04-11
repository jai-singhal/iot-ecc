from fastapi import FastAPI, Request, Response, Form
import hashlib, secrets, binascii
import base64, requests
import datetime
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
import rsa
import binascii

app = FastAPI()
db = TinyDB('db/serverdbRSA.json')#, storage=CachingMiddleware(JSONStorage))

data = {}

'''
(pu,pi)=rsa.newkeys(256) # 256/8 - 11 plain text message length
tmp=Query()
db.remove(tmp.deviceid==2)

db.update(
    {'deviceid': 2,
    'public': pu.save_pkcs1().decode('utf-8'),
    'private':pi.save_pkcs1().decode('utf-8')
},tmp.deviceid==1)

'''

@app.get('/globalparam/exchange/rsa')
def globalParamsRequestRSA(device_id:str):
    (pu,pi)=rsa.newkeys(256) # 256/8 - 11 plain text message length
    db.remove(Query().deviceid==device_id)
    db.insert(
        {'deviceid': device_id,
        'public': pu.save_pkcs1().decode('utf-8'),
        'private':pi.save_pkcs1().decode('utf-8')
    })
    params = {
        "public": pu.save_pkcs1().decode('utf-8') 
    }
    return params

@app.post('/send/msg/rsa')
def recieveMessageRSA(device_id:str,msg:str=Form(...)):
    pub_pri_pair=db.search(Query().deviceid==device_id)
    priv_key=(rsa.PrivateKey).load_pkcs1(pub_pri_pair[0]['private'])
    bytemsg=msg.encode('utf-8')
    bytemsg=binascii.unhexlify(bytemsg)
    plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
    params = {
        "secret_message": plain_text_msg
    }
    return params

@app.post('/debug/encrypt/msg/rsa')
def recieveMessageRSA(device_id:str,msg:str=Form(...)):
    pub_pri_pair=db.search(Query().deviceid==device_id)
    pub_key=(rsa.PublicKey).load_pkcs1(pub_pri_pair[0]['public'])
    bytemsg=msg.encode('utf-8')
    encrypted_text_msg=rsa.encrypt(bytemsg,pub_key)
    encrypted_text_msg=binascii.hexlify(encrypted_text_msg).decode('utf-8')
    params = {
        "secret_encrypted_message": encrypted_text_msg
    }
    return params
