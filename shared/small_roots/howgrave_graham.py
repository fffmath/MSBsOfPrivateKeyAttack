import logging

from sage.all import ZZ

from shared import small_roots


def modular_univariate(f, N, m, t, X, ifFlatter=False, method="groebner"):
    """
    Computes small modular roots of a univariate polynomial.
    More information: May A., "New RSA Vulnerabilities Using Lattice Reduction Methods" (Section 3.2)
    :param f: the polynomial
    :param N: the modulus
    :param m: the amount of normal shifts to use
    :param t: the amount of additional shifts to use
    :param X: an approximate bound on the roots
    :return: a generator generating small roots of the polynomial
    """
    f = f.monic().change_ring(ZZ)
    pr = f.parent()
    x = pr.gen()
    delta = f.degree()

    logging.debug("Generating shifts...")

    shifts = []
    for i in range(m):
        for j in range(delta):
            g = x ** j * N ** max(t - i, 0) * f ** i
            shifts.append(g)

    L, monomials = small_roots.create_lattice(pr, shifts, [X], order=None)
    L = small_roots.reduce_lattice(L, ifFlatter=ifFlatter)
    polynomials = small_roots.reconstruct_polynomials(L, f, N ** m, monomials, [X])
    for roots in small_roots.find_roots(pr, polynomials, method=method):
        yield roots[x],
