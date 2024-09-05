import time
import logging
from attacks.rsa.fnp import attack
from shared.partial_integer import PartialInteger
from sage.all import inverse_mod, next_prime, ZZ, PolynomialRing

logging.basicConfig(filename='attack.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

N = 13108249020538785310663414698582637064820950198561878706735851657036443398104279400414392269628309151684872817888692080177786492388735808216798861602636854119528204512459110978944427426326718715032735164557685449265721895500116475985815536552066383989026357484002903575383628750368953278488026714653548282683161945919042849688841485378686300720833155251742443628812196978857993634225342593766658498158262129054566502609859174903015093105430602002435138648777444747641303536985435575247992198372168117768802283641678934137582562535007550464041601241500341808273695609938403611734357471580735947449865433515838599015767
p = 124757161894632774711681251604584535395767177599048608189589501201482534891974371957818466977782123012555007070440489557620452941396889634025921970794255590369593505603793752936553527919383799909383036075989976530118664809548480153971818956174912203077504115908974119391542269233365957211095336385587786710643
q = N // p
phi = (p - 1) * (q - 1)

ebits = 257
msbs = 1280
enumeration = 0
m=75
thetaLogN = 3

e = 2**(ebits-1) + 1
d = inverse_mod(e, phi)
k= int((e*d-1)/phi)

ifFlatter = True

start_time = time.time()
result = attack(N, e, PartialInteger.msb_of(d, 2048, msbs), m=m, k=k, thetaLogN=thetaLogN,  enumeration=enumeration, ifFlatter=ifFlatter, p=p)
print(result)
print("Time:",time.time()-start_time)


'''
ebits = 17
msbs = 1536
enumeration = 0
m=75
thetaLogN = 3

ebits = 129
msbs = 1408
enumeration = 0
m=75
thetaLogN = 3

ebits = 257
msbs = 1280
enumeration = 0
m=75
thetaLogN = 3
'''
