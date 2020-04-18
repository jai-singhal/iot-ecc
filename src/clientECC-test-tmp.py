import secrets, binascii
from utils import ecc
import pickle, time, json
import random
import uuid
import sys, os
from timeit import default_timer as timer
from tqdm import tqdm

def getUIntFromPoint(p,gen,max_field):
    count=0
    tmp_p=gen
    while(tmp_p!=p):
        #print("not equal")
        tmp_p=tmp_p+gen
        count+=1
        if count>=max_field:
            return False
    return count

def getPointFromUInt(val,gen,max_field):
    if val>=max_field:
        return False
    return val*gen

if __name__ == "__main__":
    curve = ecc.getCurve(ecc.get_curve_name(6))
    if curve == None:
        print("curve error")
    tick = timer()
    privateKey = secrets.randbelow(curve.field.n)
    point1 = 1*curve.g # privKey*curve
    point2 = 2*curve.g
    point3 = 3*curve.g
    point_n = (curve.field.n)*curve.g
    print(curve.field.n)
    if point1-point3==point2:
        print("equal #1")
    elif point3-point1==point_n-point2:
        print("equal #2")
    else:
        print("not equal")

    if curve.field.n*point1==point1:
        print("points are equal")
    if curve.field.n*point1+point1==point1:
        print("point + 1 is equal")
    
    getUIntFromPoint(10000*curve.g,curve.g,curve.field.n)


"""
sb = 15, sw = 3
x = BASE_VAL + 15 + sw*32
xi = x*(curve.g)

rv = xi + sec
//send rv
// revive rv

rv = Point()
xi = rv - sec || sec - rv


"""

    #print(curve.field.n)
    #print(curve.g)
    #print(point1)
    #print(point2)
    #print(point3)