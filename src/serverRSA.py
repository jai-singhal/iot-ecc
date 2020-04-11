from fastapi import FastAPI, Request, Response, Form
import hashlib, secrets, binascii
import base64, requests
import datetime
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
import rsa
import binascii
import time
from timeit import default_timer as timer

app = FastAPI()
dbRSA = TinyDB('db/serverdbRSA.json', indent=4, separators=(',', ': '), default_table="device_pub_priv")#, storage=CachingMiddleware(JSONStorage))
dbRSATime = TinyDB('db/serverdbRSA.json', indent=4, separators=(',', ': '), default_table="timing")#, storage=CachingMiddleware(JSONStorage))
MAX_RSA_DB_ENTRY_LENGTH=2048

"""
(pu,pi)=rsa.newkeys(256) # 256/8 - 11 plain text message length
tmp=Query()
dbRSA.remove(tmp.deviceid==2)

dbRSA.update(
    {'deviceid': 2,
    'public': pu.save_pkcs1().decode('utf-8'),
    'private':pi.save_pkcs1().decode('utf-8')
},tmp.deviceid==1)

dbRSATime.insert(
    {
        'transaction_id': 12,
        'key_gen_time': 0.2132131,
        'decrypt_msg': 0.3213123,
        'encrypt_msg': 0.5345432,
        'msg_length': 234
    }
)
"""
@app.get('/rsa/get/keyexchange')
def globalParamsRequestRSA(device_id:str,key_size:int=None,transaction_id:str=None):
    if key_size is None:
        key_size = 2048
    start=timer()*(10**9)
    (pu,pi)=rsa.newkeys(key_size) # 256/8 - 11 plain text message length
    end=timer()*(10**9)
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
    start=timer()*(10**9)
    bytemsg=msg.encode('utf-8')
    bytemsg=binascii.unhexlify(bytemsg)
    plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
    end=timer()*(10**9)
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
    start=timer()*(10**9)
    bytemsg=msg.encode('utf-8')
    bytemsg=binascii.unhexlify(bytemsg)
    plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
    end=timer()*(10**9)
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
    start=timer()*(10**9)
    for msg_ind in range(0,len(msg),byte_max_msg_size):
        mod_msg=msg[msg_ind:msg_ind+byte_max_msg_size]
        bytemsg=mod_msg.encode('utf-8')
        bytemsg=binascii.unhexlify(bytemsg)
        plain_text_msg=rsa.decrypt(bytemsg,priv_key).decode('utf-8')
        complete_plain_text.append(plain_text_msg)
    end=timer()*(10**9)
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
