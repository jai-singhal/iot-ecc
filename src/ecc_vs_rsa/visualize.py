from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

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

def visualize_ecc():
    data_info = []
    for row in dbECC:
        data_info.append(row)

    kdf = pd.DataFrame(data_info)
    del kdf["deviceid"]
    del kdf["longitude"]
    del kdf["latitude"]
    del kdf["curve_name"]
    del kdf["created_at"]
    del kdf["secretKey"]

    avg_keygentime = kdf["keygen_time"].mean()
    avg_keygentime = '%.3f' %(avg_keygentime) + "ms"

    data = []
    for row in dbECCData:
        data.append(row)

    df = pd.DataFrame(data)
    del df["transaction_id"]
    del df["filepath"]
    del df["keysize"]

    meandf = df.groupby(["msg_len"]).mean()
    meandf.sort_values("msg_len")
    meandf["encrypt_time"] = meandf["encrypt_time"]
    meandf["decrypt_time"] = meandf["decrypt_time"]
    meandf["total_time"] = meandf["total_time"]

    ax = meandf.plot(rot=0,  use_index=True, kind='bar', title='Time vs message size')
    print("Avg Key-generation time: " + avg_keygentime)
    plt.text(-0.25, 26.5, "Avg Key-generation time: " + avg_keygentime)

    plt.xlabel("Message Length (in KB)")
    plt.ylabel("Time required (in ms)")
    plt.legend(['Encryption time', 'Decryption time', 'Total time'])

    plt.show()



def visualize_rsa():
    data = []
    for row in dbRSATime:
        data.append(row)

    df = pd.DataFrame(data)
    del df["transaction_id"]
    del df["device_id"]
    del df["key_size"]
    del df["plain_text_msg"]

    total_time_list=[]
    for index, i in df.iterrows():
        total_time_list.append(i["encrypt_msg"]+i["decrypt_msg"]+i["key_gen_time"])

    df['total_time']=total_time_list
    df["msg_length"]=df["msg_length"]/1000

    meandf = df.groupby(["msg_length"]).mean()
    meandf.sort_values("msg_length")
    meandf["key_gen_time"] = meandf["key_gen_time"]
    meandf["encrypt_msg"] = meandf["encrypt_msg"]
    meandf["decrypt_msg"] = meandf["decrypt_msg"]
    meandf["total_time"] = meandf["total_time"]

    ax = meandf.plot(rot=0,  use_index=True, kind='bar', title='Time vs message size')
    plt.xlabel("Message Length (in KB)")
    plt.ylabel("Time required (in ms)")
    plt.legend(['keygen time', 'Decryption time', 'Encryption time', 'Total time(ms)'])
    # ax.show()
    plt.show()


if __name__ == "__main__":
    visualize_ecc()
    visualize_rsa()