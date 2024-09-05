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
    """
    Return the prime factors of RSA modulus by solving small roots of univariate polynomials.

    :param e: the public exponent
    :param f: univariate polynomials to be solved
    :param N: the modulus
    :param m: the m value to use for the small roots method 
    :param t: the t value to use for the small roots method
    :param X: bound for small roots
    :ifFlatter: for faster LLL-reduction

    :return: a tuple containing the prime factors, or None if the factors were not found
    """
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
            
def _fnp_theorem_1(N, e, d_bit_length, d1, d1_bit_length, m, t, thetaLogN=None, k=None, ifFlatter=False, known_p=None):
    """
    Return the prime factors of RSA modulus using MSBs of d based on the Feng-Nitaj-Pan (FNP) attack (Theorem 1).

    :param N: the modulus
    :param e: the public exponent
    :param d_bit_length: bit length of the private exponent d
    :param d1: known most significant bits (MSBs) of d
    :param d1_bit_length: bit length of d1 (the number of known MSBs)
    :param m: the m value to use for the small roots method 
    :param t: the t value to use for the small roots method
    :param thetaLogN: related to the bound used in Coppersmith’s method (optional)
    :param k: k=(ed-1)/phi (optional)
    :param ifFlatter: for faster LLL-reduction (optional)
    :param known_p: optional known value of prime factor p (optional)

    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    logging.info(f"Trying {m = }, {t = }...")
    p = Zmod(e)["p"].gen()
    x = Zmod(N)["x"].gen()
    X = int(2**(thetaLogN)*RR(N)/(e*2**d1_bit_length))
    if k is not None:
        d0 = d1 << (d_bit_length - d1_bit_length)
        S = int(N+1-((e*d0-1)//k))
        D = int(sqrt(S*S-4*N))
        pApproximation = int((S+D)//2)
        logging.debug(f"Trying an approximation of : pApproximation={pApproximation}")
        f = k * p ** 2 - (1 + k * (N + 1)) * p + k * N
        rootsList = f.roots(multiplicities=False)
        print(f"There are {len(rootsList)} possibilities for p mod e")
        for p0 in rootsList:
            p0 = int(p0)
            logging.debug(f"Trying p0 = {p0}")
            tApproximation = (pApproximation-p0)//e
            logging.debug(f"Trying an approximation of : tApproximation={tApproximation}")
            if known_p is not None:
                delta_t = abs((known_p-known_p%e)//e-tApproximation)
                logging.debug(f"Solving univariate equation with {int(delta_t).bit_length()} bits")
                print(f"Solving univariate equation with {int(delta_t).bit_length()} bits")
            logging.debug(f"Set coppersmith bound {int(X).bit_length()} bits")
            print(f"Set coppersmith bound {int(X).bit_length()} bits")
            f = (x+tApproximation) * e + int(p0)
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
            f = k * p ** 2 - (1 + k * (N + 1)) * p + k * N
            rootsList = f.roots(multiplicities=False)
            print(f"There are {len(rootsList)} possibilities for p mod e")
            for p0 in rootsList:
                p0 = int(p0)
                logging.debug(f"Trying p0 = {p0}")
                tApproximation = (pApproximation-p0)//e
                logging.debug(f"Trying an approximation of : tApproximation={tApproximation}")
                if known_p is not None:
                    delta_t = abs((known_p-known_p%e)//e-tApproximation)
                    logging.debug(f"Solving univariate equation with {int(delta_t).bit_length()} bits")
                    print(f"Solving univariate equation with {int(delta_t).bit_length()} bits")
                print(f"Set coppersmith bound {int(X).bit_length()} bits")
                f = (x+tApproximation) * e + int(p0)
                for p_, q_, d_ in _bdf_corollary_1(e, f, N, m, t, X, ifFlatter=ifFlatter):
                    return p_, q_, d_

    return None

def attack(N, e, partial_d, factor_e=True, m=1, t=None, k=None, thetaLogN= None, enumeration=0, ifFlatter=False, p=None):
    """
    Perform an RSA key recovery attack using partial information of the private key exponent d. 
    Based on the Feng-Nitaj-Pan (FNP) Theorem 1 approach.

    :param N: the modulus
    :param e: the public exponent
    :param partial_d: partial information of d
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: None)
    :param k: k=(ed-1)/phi (optional)
    :param thetaLogN: related to the bound used in Coppersmith's method (optional)
    :param enumeration: necessary enumeration when the rood exceeds Coppersmith's bound (default: 0)
    :param ifFlatter: for faster LLL-reduction (optional)
    :param p: optional known value of prime factor p (optional)

    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    d_bit_length = partial_d.bit_length
    d1, d1_bit_length = partial_d.get_known_msb()
    assert d1_bit_length > 0 and d1_bit_length+enumeration<=d_bit_length, "At least some lsb or msb of d must be known."

    n = N.bit_length()

    t_ = e.bit_length() - 1
    alpha = t_ / n
    beta = d_bit_length / n
    assert beta >= 0.25, "Use Wiener's or the Boneh-Durfee attack if d is very small."

    logging.info("Using Feng-Nitaj-Pan (Theorem 1)...")
    t = int(1/2 * m) if t is None else t
    for enumeration_bits in range(2**enumeration):
        d1_bit_length_new = d1_bit_length+enumeration
        d1_new = d1*2**enumeration + enumeration_bits
        result = _fnp_theorem_1(N, e, d_bit_length, d1_new, d1_bit_length_new, m, t, k=k, thetaLogN=thetaLogN, ifFlatter=ifFlatter, known_p=p)
        if result != None:
            return result
    return None