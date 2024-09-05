import time
import logging
from attacks.rsa.bdf import attack
from shared.partial_integer import PartialInteger
from sage.all import inverse_mod, next_prime, ZZ, PolynomialRing

logging.basicConfig(filename='attack.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

q = 8409994693249896404784904531467076591669926559983707531327683517189185536127617166572882422715355263943409904919761519989515813520595114890263313096406517
p = 13332483168606238737181696873100104751420317885066608062141583458038224144727215840015557177200814570451949655836044414422384438369627145548625958519764109
N = p * q
phi = (p - 1) * (q - 1)

ebits = 17
msbs = 988
enumeration = 0
m=3
thetaLogN = 2

e = 2**(ebits-1) + 1
d = inverse_mod(e, phi)
k= int((e*d-1)/phi)

ifFlatter = False

start_time = time.time()
result = attack(N, e, PartialInteger.msb_of(d, 1024, msbs), m=m, k=k, thetaLogN=thetaLogN,  enumeration=enumeration, ifFlatter=ifFlatter, p=p)
print(result)
print("Time:",time.time()-start_time)

'''
ebits = 17
msbs = 768
enumeration = 7
m=75
thetaLogN = 2

ebits = 129
msbs = 768
enumeration = 6
m=75
thetaLogN = 2
'''