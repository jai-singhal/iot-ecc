import pandas as pd
import matplotlib.pyplot as plt
import re
from functools import reduce
  
def average(lst): 
    return reduce(lambda a, b: a + b, lst) / len(lst)

def getData(logName):
    verifier = list()
    prover = list()
    total = list()
    mac_gen = list()
    sig_gen = list()

    with open(logName, "r") as fin:
        fread = fin.read().split("\n")
        for i in range(1, len(fread), 5):
            try:
                mac_gen.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+0])[0]))
                sig_gen.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+1])[0]))
                verifier.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+2])[0]))
                prover.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+3])[0]))
                total.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+4])[0]))
            
            except:
                pass
         
    return (mac_gen, sig_gen, verifier, prover, total)


mac_gen64, sig_gen64, verifer64, prover64, total64 = getData("../../logs/review_mod_logs/verifier_64KB.log")

mac_gen128, sig_gen128, verifer128, prover128, total128 = getData("../../logs/review_mod_logs/verifier_128KB.log")
mac_gen256, sig_gen256, verifer256, prover256, total256 = getData("../../logs/review_mod_logs/verifier_256KB.log")
mac_gen512, sig_gen512, verifer512, prover512, total512 = getData("../../logs/review_mod_logs/verifier_512KB.log")
mac_gen1, sig_gen1, verifer1, prover1, total1 = getData("../../logs/review_mod_logs/verifier_1MB.log")
mac_gen2, sig_gen2, verifer2, prover2, total2 = getData("../../logs/review_mod_logs/verifier_2MB.log")

mac_gen4, sig_gen4, verifer4, prover4, total4 = getData("../../logs/review_mod_logs/verifier_4MB.log")

print(average(mac_gen128), average(sig_gen128), average(verifer128), average(prover128), average(total128))
print(average(mac_gen256), average(sig_gen256), average(verifer256), average(prover256), average(total256))
print(average(mac_gen512), average(sig_gen512), average(verifer512), average(prover512), average(total512))
print(average(mac_gen1), average(sig_gen1), average(verifer1), average(prover1), average(total1))
print(average(mac_gen2), average(sig_gen2), average(verifer2), average(prover2), average(total2))
print(average(mac_gen4), average(sig_gen4), average(verifer4), average(prover4), average(total4))


total_dp = len(total64)
x = [i for i in range(total_dp)]
plt.plot(x, total64, color='r')
plt.plot(x, total128, color='g')
plt.plot(x, total256, color='b')
plt.plot(x, total512, color='y')

plt.plot(x, total1, color='c')
plt.plot(x, total2, color='m')
plt.plot(x, total4, color='k')


plt.xlabel('Iterations') 
plt.ylabel('Total time taken in(ms)') 
plt.title('Attestation ') 
plt.legend(['64KB Block size', '128KB Block size', '256KB Block size', '512KB Block size', '1MB Block Size', '2 MB Block Size', '4MB Block Size'])
plt.text(-0.5, 118.40, "Avg Key-generation time: " + "553.7 ms")


plt.show()
