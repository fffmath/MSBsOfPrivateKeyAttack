import time
import logging
from attacks.rsa.fnp import attack
from shared.partial_integer import PartialInteger
from sage.all import inverse_mod, next_prime, ZZ, PolynomialRing

logging.basicConfig(filename='attack.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

q = 16158503035655503650357438344334975980222051334857742016065172713762327569433945446598600705761456731844358980460949009747059779575245460547544076193224141560315438683650498045875098875194826053398028819192033784138396109321309878080919047169238085235290822926018152521443787945770532904303776199561965192760957166694834171210342487393282284747428088017663161029038902829665513096354230157075129296432088558362971801859230928678799175576150822952201848806616643615613562842355410104862578550863465661734839271290328348967522998634176499319107762583194718667771801067716614802322659239302476074096777926805529798117247
p = 24237754553483255475536157516502463970333077002286613024097759070643491354150918169897901058642185097766538470691423514620589669362868190821316114289836212340473158025475747068812648312792239080097043228788050676207594163981964817121378570753857127852936234389027228782165681918655799356455664299342947789141435750042251256815513731089923427121142132026494741543558354244498269644531345235612693944648132837544457702788846393018198763364226234428302773209924965423420344263533115157293867826295198492602258906935492523451284497951264748978661643874792078001657701601574922203483988858953714111145166890208294697173431
N = p * q
phi = (p - 1) * (q - 1)

ebits = 17
msbs = 3072
enumeration = 0
m=75
thetaLogN = 3

e = 2**(ebits-1) + 1
d = inverse_mod(e, phi)
k= int((e*d-1)/phi)

ifFlatter = True

start_time = time.time()
result = attack(N, e, PartialInteger.msb_of(d, 4096, msbs), m=m, k=k, thetaLogN=thetaLogN,  enumeration=enumeration, ifFlatter=ifFlatter, p=p)
print(result)
print("Time:",time.time()-start_time)