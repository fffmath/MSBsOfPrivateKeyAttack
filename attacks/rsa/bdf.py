import logging
import os
import sys
from math import ceil
from math import gcd
from math import sqrt

from sage.all import QQ
from sage.all import RR
from sage.all import ZZ
from sage.all import Zmod
from sage.all import is_prime
from sage.all import sqrt

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import howgrave_graham


def _bdf_corollary_1(e, f, N, m, t, X, ifFlatter=False):
    logging.debug(f"Solving f wiht root x0=0")
    p = abs(int(f(0)))
    if 1 < p < N and N % p == 0:
        q = N // p
        phi = (p - 1) * (q - 1)
        yield p, q, pow(e, -1, phi)
    for x0, in howgrave_graham.modular_univariate(f, N, m, t, X, ifFlatter=ifFlatter):
        logging.debug(f"Solving f wiht root x0={x0}")
        p = abs(int(f(x0)))
        if 1 < p < N and N % p == 0:
            q = N // p
            phi = (p - 1) * (q - 1)
            yield p, q, pow(e, -1, phi)    
            
def _bdf_theorem_3_3(N, e, d_bit_length, d1, d1_bit_length, m, t, thetaLogN=None, k=None, ifFlatter=False, known_p=None):
    logging.info(f"Trying {m = }, {t = }...")
    p = Zmod(e)["p"].gen()
    x = Zmod(N)["x"].gen()
    X = int(2**(thetaLogN)*RR(N)/(2**d1_bit_length))
    if k is not None:
        d0 = d1 << (d_bit_length - d1_bit_length)
        S = int(N+1-((e*d0-1)//k))
        D = int(sqrt(S*S-4*N))
        pApproximation = int((S+D)//2)
        logging.debug(f"Trying an approximation of : pApproximation={pApproximation}")
        if known_p is not None:
            delta_p = abs(known_p-pApproximation)
            logging.debug(f"Solving univariate equation with {int(delta_p).bit_length()} bits")
            print(f"Solving univariate equation with {int(delta_p).bit_length()} bits")
        logging.debug(f"Set coppersmith bound {int(X).bit_length()} bits")
        print(f"Set coppersmith bound {int(X).bit_length()} bits")
        f = x + pApproximation
        for p_, q_, d_ in _bdf_corollary_1(e, f, N, m, t, X, ifFlatter=ifFlatter):
            return p_, q_, d_
            
    else:
        d0 = d1 << (d_bit_length - d1_bit_length)
        k_ = (e * d0 - 1) // N
        logging.info("Generating solutions for k candidates...")
        for k in range(k_ - 14, k_ + 14):
            S = int(N+1-(e*d0-1)//k)
            D = int(sqrt(S**2-4*N))
            pApproximation = int((S+D)//2)
            print(f"Solving RSA with k={k}")
            logging.debug(f"Solving RSA with k={k}")
            if known_p is not None:
                delta_p = abs(known_p-pApproximation)
                logging.debug(f"Solving univariate equation with {int(delta_p).bit_length()} bits")
                print(f"Solving univariate equation with {int(delta_p).bit_length()} bits")
            logging.debug(f"Set coppersmith bound {int(X).bit_length()} bits")
            print(f"Set coppersmith bound {int(X).bit_length()} bits")
            f = x + pApproximation
            for p_, q_, d_ in _bdf_corollary_1(e, f, N, m, t, X, ifFlatter=ifFlatter):
                return p_, q_, d_

    return None

def attack(N, e, partial_d, factor_e=True, m=1, t=None, k=None, thetaLogN= None, enumeration=0, ifFlatter=False, p=None):

    d_bit_length = partial_d.bit_length
    d1, d1_bit_length = partial_d.get_known_msb()
    assert d1_bit_length > 0 and d1_bit_length+enumeration<=d_bit_length, "At least some lsb or msb of d must be known."

    n = N.bit_length()

    t_ = e.bit_length() - 1
    alpha = t_ / n
    beta = d_bit_length / n
    assert beta >= 0.25, "Use Wiener's or the Boneh-Durfee attack if d is very small."

    logging.info("Using Boneh-Durfee-Frankel (Theorem 3.3)...")
    t = int(1/2 * m) if t is None else t
    for enumeration_bits in range(2**enumeration):
        d1_bit_length_new = d1_bit_length+enumeration
        d1_new = d1*2**enumeration + enumeration_bits
        result = _bdf_theorem_3_3(N, e, d_bit_length, d1_new, d1_bit_length_new, m, t, k=k, thetaLogN=thetaLogN, ifFlatter=ifFlatter, known_p=p)
        if result != None:
            return result
    return None