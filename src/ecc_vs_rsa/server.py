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
from timeit import default_timer as timer

app = FastAPI()
# https://pypi.org/project/tinydb/
dbECC = TinyDB('../../db/serverdbECC.json', 
    indent=4, separators=(',', ': '), 
    default_table="device_info",
    # storage=CachingMiddleware(JSONStorage)
)
dbECCData = TinyDB('../../db/serverdbECC.json', 
    indent=4, separators=(',', ': '), 
    default_table="data",
    # storage=CachingMiddleware(JSONStorage)
)
dbRSA = TinyDB('../../db/serverdbRSA.json', 
    indent=4, separators=(',', ': '),
    default_table="device_pub_priv",
    # storage=CachingMiddleware(JSONStorage)
)
dbRSATime = TinyDB('../../db/serverdbRSA.json', 
    indent=4, separators=(',', ': '),
    default_table="timing",
    # storage=CachingMiddleware(JSONStorage)
)



MAX_RSA_DB_ENTRY_LENGTH=2048


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
def ecc_getClientGlobalParams(cli:ClientParams):
    try:
        ClientQ = Query()
        print(dbECC.get(ClientQ.deviceid == cli.device_id))

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


@app.post('/ecc/post/keyexchange/')
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
        total_time += (tock-tick)*(10**3)
        tick = timer()
        secretKey = ecc.ecc_point_to_256_bit_key(privateKey*clientPubKey)
        tock = timer()
        total_time += 2*(tock-tick)*(10**3) # 2time key gen
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


@app.post('/ecc/send/msg/')
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
    decr_time = (tock-tick)*(10**3)
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

########################### RSA ############################
"""
/rsa/get/keyexchange
/rsa/post/msg
/rsa/post/stepwise/msg
/rsa/post/big/msg
/rsa/post/big/msg/file
/rsa/send/time/encrypt
/rsa/debug/encrypt/msg
/rsa/performance
/rsa/prebuiltkeys/timer
"""
@app.get('/rsa/prebuiltkeys/timer')
def usePreviousKeysRequestRSA(device_id:str,transaction_id:int=None):
    init_data=dbRSATime.search(Query().device_id==device_id)[0]
    if transaction_id is None:
        transaction_id=str(len(dbRSATime))
    dbRSATime.remove(Query().transaction_id==transaction_id)
    dbRSATime.insert(
        {
            'device_id': device_id,
            'transaction_id': transaction_id,
            'key_gen_time': init_data['key_gen_time'],
            'key_size': init_data['key_size'],
            'decrypt_msg': 0.0,
            'encrypt_msg': 0.0,
            'msg_length': 0,
            'plain_text_msg':""
        }
    )
    params = {
        "transaction_id": transaction_id
    }
    return params

@app.get('/rsa/get/keyexchange')
def globalParamsRequestRSA(device_id:str,key_size:int=None,transaction_id:str=None):
    if key_size is None:
        key_size = 2048
    start=timer()*(10**3)
    (pu,pi)=rsa.newkeys(key_size) # 256/8 - 11 plain text message length
    end=timer()*(10**3)
    dbRSA.remove(Query().deviceid==device_id)
    dbRSA.insert(
        {
            'deviceid': device_id,
            'public': pu.save_pkcs1().decode('utf-8'),
            'private':pi.save_pkcs1().decode('utf-8')
        }
    )
    if transaction_id is None:
        transaction_id=str(len(dbRSATime))
    dbRSATime.remove(Query().transaction_id==transaction_id)
    dbRSATime.insert(
        {
            'device_id': device_id,
            'transaction_id': transaction_id,
            'key_gen_time': end-start,
            'key_size': key_size,
            'decrypt_msg': 0.0,
            'encrypt_msg': 0.0,
            'msg_length': 0,
            'plain_text_msg':""
        }
    )
    params = {
        "public": pu.save_pkcs1().decode('utf-8'),
        "transaction_id": transaction_id
    }
    return params

@app.post('/rsa/post/msg')
def recieveMessageRSA(device_id:str,transaction_id:str,msg:str=Form(...)):
    pub_pri_pair=dbRSA.search(Query().deviceid==device_id)
    priv_key=(rsa.PrivateKey).load_pkcs1(pub_pri_pair[0]['private'])
    start=timer()*(10**3)
    bytemsg=msg.encode('utf-8')
    bytemsg=binascii.unhexlify(bytemsg)
    plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
    end=timer()*(10**3)
    print(end-start)
    print("message sent by client "+str(device_id)+": "+msg)
    print("decrypted message from client "+str(device_id)+": "+plain_text_msg)
    dbRSATime.update(
        {
            'decrypt_msg': end-start,
            'msg_length': len(plain_text_msg),
            'plain_text_msg': plain_text_msg
        }
    ,Query().transaction_id==transaction_id)
    params = {
        "secret_message": plain_text_msg
    }
    return params

@app.post('/rsa/post/stepwise/msg')
def recieveMessageStepwiseRSA(device_id:str,transaction_id:str,msg:str=Form(...)):
    pub_pri_pair=dbRSA.search(Query().deviceid==device_id)
    priv_key=(rsa.PrivateKey).load_pkcs1(pub_pri_pair[0]['private'])
    start=timer()*(10**3)
    bytemsg=msg.encode('utf-8')
    bytemsg=binascii.unhexlify(bytemsg)
    plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
    end=timer()*(10**3)
    #print(end-start)
    #print("message sent by client "+str(device_id)+": "+msg)
    #print("decrypted message from client "+str(device_id)+": "+plain_text_msg)
    partial_data=dbRSATime.search(Query().transaction_id==transaction_id)
    dbRSATime.update(
        {
            'decrypt_msg': partial_data[0]['decrypt_msg']+end-start,
            'msg_length': partial_data[0]['msg_length']+len(plain_text_msg),
            'plain_text_msg': partial_data[0]['plain_text_msg']+plain_text_msg
        }
    ,Query().transaction_id==transaction_id)
    params = {
        "secret_message": plain_text_msg
    }
    return params

@app.post('/rsa/post/big/msg')
def recieveMessageBigRSA(device_id:str,transaction_id:str,msg:str=Form(...)):
    pub_pri_pair=dbRSA.search(Query().deviceid==device_id)
    priv_key=(rsa.PrivateKey).load_pkcs1(pub_pri_pair[0]['private'])
    partial_data=dbRSATime.search(Query().transaction_id==transaction_id)
    byte_max_msg_size=partial_data[0]['key_size']//4
    complete_plain_text=[]
    start=timer()*(10**3)
    for msg_ind in range(0,len(msg),byte_max_msg_size):
        mod_msg=msg[msg_ind:msg_ind+byte_max_msg_size]
        bytemsg=mod_msg.encode('utf-8')
        bytemsg=binascii.unhexlify(bytemsg)
        plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
        complete_plain_text.append(plain_text_msg)
    end=timer()*(10**3)
    complete_plain_text=''.join(complete_plain_text)
    msg_len=len(complete_plain_text)
    if(len(complete_plain_text)>MAX_RSA_DB_ENTRY_LENGTH):
        complete_plain_text="very big message!!"
    dbRSATime.update(
        {
            'decrypt_msg': end-start,
            'msg_length': msg_len,
            'plain_text_msg': complete_plain_text
        }
    ,Query().transaction_id==transaction_id)
    params = {
        "secret_message": complete_plain_text
    }
    return params

@app.post('/rsa/post/big/msg/file')
def recieveMessageBigFileRSA(device_id:str,transaction_id:str,tmp_file:UploadFile=File(...)):
    msg=tmp_file.file.read().decode('utf-8')
    pub_pri_pair=dbRSA.search(Query().deviceid==device_id)
    priv_key=(rsa.PrivateKey).load_pkcs1(pub_pri_pair[0]['private'])
    partial_data=dbRSATime.search(Query().transaction_id==transaction_id)
    byte_max_msg_size=partial_data[0]['key_size']//4
    complete_plain_text=[]
    start=timer()*(10**3)
    for msg_ind in range(0,len(msg),byte_max_msg_size):
        mod_msg=msg[msg_ind:msg_ind+byte_max_msg_size]
        bytemsg=mod_msg.encode('utf-8')
        bytemsg=binascii.unhexlify(bytemsg)
        plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
        complete_plain_text.append(plain_text_msg)
    end=timer()*(10**3)
    complete_plain_text=''.join(complete_plain_text)
    msg_len=len(complete_plain_text)
    if(len(complete_plain_text)>MAX_RSA_DB_ENTRY_LENGTH):
        complete_plain_text="very big message!!"
    dbRSATime.update(
        {
            'decrypt_msg': end-start,
            'msg_length': msg_len,
            'plain_text_msg': complete_plain_text
        }
    ,Query().transaction_id==transaction_id)
    params = {
        "secret_message": complete_plain_text
    }
    return params

@app.get('/rsa/send/time/encrypt')
def recieveEncryptionTimeRSA(transaction_id:str,encrypt_time:float):
    dbRSATime.update(
        {
            'encrypt_msg': encrypt_time
        }
    ,Query().transaction_id==transaction_id)
    return "Successfully updated"

@app.post('/rsa/debug/encrypt/msg')
def debugGetEncryptedFromPlainRSA(device_id:str,msg:str=Form(...)):
    mod_msg=msg
    pub_pri_pair=dbRSA.search(Query().deviceid==device_id)
    pub_key=(rsa.PublicKey).load_pkcs1(pub_pri_pair[0]['public'])
    bytemsg=rsa.encrypt(mod_msg.encode('utf-8'),pub_key)
    rtnmsg=binascii.hexlify(bytemsg)
    encryptedMsgObj=rtnmsg.decode('utf-8')
    return encryptedMsgObj

@app.get('/rsa/performance')
def performanceRSA():
    res=dict()
    res["consolidated"]=dict()
    timeValues=dbRSATime.all()
    totalTime=0
    rows=len(timeValues)
    for index in range(rows):
        if(not str(timeValues[index]['key_size']) in res):
            res[str(timeValues[index]['key_size'])]=list()
        tmp_dict=dict()
        tmp_dict['key_gen_time']=timeValues[index]['key_gen_time']
        tmp_dict['decrypt_msg']=timeValues[index]['decrypt_msg']
        tmp_dict['encrypt_msg']=timeValues[index]['encrypt_msg']
        tmp_dict["total_time"]=\
            timeValues[index]['key_gen_time']+\
            timeValues[index]['decrypt_msg']+\
            timeValues[index]['encrypt_msg']
        res[str(timeValues[index]['key_size'])].append(tmp_dict)
        if(not str(timeValues[index]['key_size']) in res["consolidated"]):
            res["consolidated"][str(timeValues[index]['key_size'])]=dict()
            res["consolidated"][str(timeValues[index]['key_size'])]["total_test_time"]=0
            res["consolidated"][str(timeValues[index]['key_size'])]["total_test_key_gen_time"]=0
            res["consolidated"][str(timeValues[index]['key_size'])]["total_test_decrypt_msg_time"]=0
            res["consolidated"][str(timeValues[index]['key_size'])]["total_test_encrypt_msg_time"]=0
        res["consolidated"][str(timeValues[index]['key_size'])]["total_test_time"]+=\
            tmp_dict["total_time"]
        res["consolidated"][str(timeValues[index]['key_size'])]["total_test_key_gen_time"]+=\
            tmp_dict['key_gen_time']
        res["consolidated"][str(timeValues[index]['key_size'])]["total_test_decrypt_msg_time"]+=\
            tmp_dict['decrypt_msg']
        res["consolidated"][str(timeValues[index]['key_size'])]["total_test_encrypt_msg_time"]+=\
            tmp_dict['encrypt_msg']
    for key_size in res["consolidated"]:
        #len(res[key_size])
        params=["total_test_time","total_test_key_gen_time","total_test_decrypt_msg_time","total_test_encrypt_msg_time"]
        for key in params:
            avg=res["consolidated"][key_size][key]/len(res[key_size])
            res["consolidated"][key_size]["avg_"+key]=avg

    params = {
        "data": res
    }
    return params
