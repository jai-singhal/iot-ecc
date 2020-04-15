from Crypto.Hash import SHA256
from timeit import default_timer as timer

def create_sha256_hash(msg:str):
    h = SHA256.new()
    h.update(msg.encode("utf-8"))
    return h.hexdigest()

filepath="../../memory/memoryFile_prover.txt"

with open(filepath, "r") as fin:
	fcontent = fin.read()	            
	tick = timer()
	hashDig=create_sha256_hash(fcontent)
	toc = timer()
	print("time taken : "+str((toc-tick)*(10**3))+" ms")
	print("hash digest : "+str(hashDig))
