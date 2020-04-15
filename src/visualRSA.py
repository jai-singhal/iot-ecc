from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from PIL import _imaging
import pandas as pd
import matplotlib.pyplot as plt

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
meandf["key_gen_time"] = meandf["key_gen_time"]/10**6
meandf["encrypt_msg"] = meandf["encrypt_msg"]/10**6
meandf["decrypt_msg"] = meandf["decrypt_msg"]/10**6
meandf["total_time"] = meandf["total_time"]/10**6

ax = meandf.plot(rot=0,  use_index=True, kind='bar', title='Time vs message size')
plt.xlabel("Message Length (in KB)")
plt.ylabel("Time required (in ms)")
plt.legend(['keygen time','Encryption time', 'Decryption time', 'Total time'])
# ax.show()
plt.show()
