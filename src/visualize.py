from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# https://pypi.org/project/tinydb/
dbECC = TinyDB('../db/serverdbECC.json', 
    indent=4, separators=(',', ': '), 
    default_table="device_info",
    # storage=CachingMiddleware(JSONStorage)
)
dbECCData = TinyDB('../db/serverdbECC.json', 
    indent=4, separators=(',', ': '), 
    default_table="data",
    # storage=CachingMiddleware(JSONStorage)
)
dbRSA = TinyDB('../db/serverdbRSA.json', 
    indent=4, separators=(',', ': '),
    default_table="device_pub_priv",
    # storage=CachingMiddleware(JSONStorage)
)
dbRSATime = TinyDB('../db/serverdbRSA.json', 
    indent=4, separators=(',', ': '),
    default_table="timing",
    # storage=CachingMiddleware(JSONStorage)
)

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
avg_keygentime = '%.3f' %(avg_keygentime/10**6) + "ms"

data = []
for row in dbECCData:
    data.append(row)

df = pd.DataFrame(data)
del df["transaction_id"]
del df["filepath"]
del df["keysize"]

meandf = df.groupby(["msg_len"]).mean()
meandf.sort_values("msg_len")
meandf["encrypt_time"] = meandf["encrypt_time"]/10**6
meandf["decrypt_time"] = meandf["decrypt_time"]/10**6
meandf["total_time"] = meandf["total_time"]/10**6

ax = meandf.plot(rot=0,  use_index=True, kind='bar', title='Time vs message size')

plt.text(0, 22, "Avg Key-generation time: " + avg_keygentime)
plt.xlabel("Message Length (in KB)")
plt.ylabel("Time required (in ms)")
plt.legend(['Encryption time', 'Decryption time', 'Total time'])
plt.show()


