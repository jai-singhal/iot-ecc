import pandas as pd
import matplotlib.pyplot as plt
import re

def getData(logName):
    verifier = list()
    prover = list()
    total = list()

    with open(logName, "r") as fin:
        fread = fin.read().split("\n")
        for i in range(0, len(fread), 4):
            try:
                verifier.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+0])[0]))
                prover.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+1])[0]))
                total.append(float(re.findall(r"[0-9]*\.[0-9]*", fread[i+2])[0]))
            except:
                pass
    return verifier, prover, total


verifer0_5, prover0_5, total0_5 = getData("../../logs/verifer-0.5KB.log")
verifer1, prover1, total1 = getData("../../logs/verifer-1KB.log")
verifer32, prover32, total32 = getData("../../logs/verifer-32KB.log")
verifer100, prover100, total100 = getData("../../logs/verifer-100KB.log")

total_dp = 120
seek = 200
x = [i for i in range(total_dp)]
plt.plot(x, total0_5[seek:seek+total_dp], color='r')
plt.plot(x, total1[seek:seek+total_dp], color='g')
plt.plot(x, total32[seek:seek+total_dp], color='b')
plt.plot(x, total100[seek:seek+total_dp], color='y')
plt.xlabel('Iterations') 
plt.ylabel('Total time taken in(ms)') 
plt.title('Attestation ') 
plt.legend(['0.5KB Block size', '1KB Block size', '32KB Block size', '100KB Block size'])
plt.text(-0.25, 2.40, "Avg Key-generation time: " + "553.7 ms")


plt.show()
