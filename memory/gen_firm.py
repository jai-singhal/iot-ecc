import random
import string 
  
# initializing size of string  
N = 32
  
with open("firmware_v4.hex", "w") as fout:
    for i in range(1000000):
        res = ''.join(random.choices(string.ascii_uppercase[:6] +
                                    string.digits, k = N)) 

        fout.write(res)
        fout.write("\n")
