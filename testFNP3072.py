import time
import logging
from attacks.rsa.fnp import attack
from shared.partial_integer import PartialInteger
from sage.all import inverse_mod, next_prime, ZZ, PolynomialRing

logging.basicConfig(filename='attack.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

q = 1205156213460516294290058303014157056456046623972844475679837519532628695795901600334542512053673024831724383140444002393931208489397479162484806493945387325727606669690812612385391038958840749838422771568693910028798672928952299554730693561049753982498907820671150338814736677640808714205897081983892935185184484554610795971527116005781379225040289793925450496857446141738323315590757531902436687591130253123496418949352985506262921662200616493428502380169659067
p = 1807734320190774441435087454521235584684069935959266713519756279298943043693852400501813768080509537247586574710666003590896812734096218743727209740918080988591410004536218918578086558438261124757634157353040865043198009393428449332096040341574630973748361731006725508222105016461213071308845622975839402777776726831916193957290674008672068837560434690888175745286169212607484973386136297853655031386695379685244628424029478259394382493300924740142753570254489389
N = p * q
phi = (p - 1) * (q - 1)

ebits = 17
msbs = 2304
enumeration = 0
m=75
thetaLogN = 3

e = 2**(ebits-1) + 1
d = inverse_mod(e, phi)
k= int((e*d-1)/phi)

ifFlatter = True

start_time = time.time()
result = attack(N, e, PartialInteger.msb_of(d, 3072, msbs), m=m, k=k, thetaLogN=thetaLogN,  enumeration=enumeration, ifFlatter=ifFlatter, p=p)
print(result)
print("Time:",time.time()-start_time)