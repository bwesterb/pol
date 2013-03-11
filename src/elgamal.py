""" Extensions to pycrypto's implementation of ElGamal. """

import math
import time
import logging
import threading
import itertools
import collections
import multiprocessing

# pycrypto
import Crypto.Util.number as number
import Crypto.Random

# gmpy
import gmpy

import pol.parallel
import pol.progressbar

group_parameters = collections.namedtuple('group_parameters', ('p', 'g'))

l = logging.getLogger(__name__)

# Estimates of safe prime density.
# TODO add more explanation
SAFE_PRIME_DENSITY = {
        128:  0.01493381,
        256:  0.00734759,
        512:  0.00374558,
        1024: 0.00180737,
        2048: 0.00097234 }

if not number._fastmath:
    l.warning("pycrypto not built with _fastmath module.  A lot will be quite "+
              "slow")

def _find_safe_prime_initializer(args, kwargs):
    Crypto.Random.atfork()
    kwargs['randfunc'] = Crypto.Random.new().read

def _find_safe_prime(bits, randfunc=None):
    """ Finds a safe prime of `bits` bits """
    r = gmpy.mpz(number.getRandomNBitInteger(bits-1, randfunc))
    q = gmpy.next_prime(r)
    p = 2*q+1
    if gmpy.is_prime(p):
        return p

def generate_group_params(bits=1024, nthreads=None, progress=None):
    """ Generates group parameters for ElGamal. """
    # Find a safe prime as modulus.  This will take at least several
    # seconds on a single core.  Thus: we will parallelize.
    start_time = time.time()
    if nthreads is None:
        nthreads = multiprocessing.cpu_count()
    l.debug('Searching for a %s bit safe prime p as modulus on %s threads',
                bits, nthreads)
    safe_prime_density = SAFE_PRIME_DENSITY.get(bits, 2.0 / bits)
    if progress:
        progress('p', None)
        def _progress(n):
            progress('p', pol.progressbar.coin(safe_prime_density, n))
    else:
        _progress = None
    p = pol.parallel.parallel_try(_find_safe_prime, (bits,),
                            initializer=_find_safe_prime_initializer,
                            progress=_progress, nthreads=nthreads)
    # Find a safe `g` as generator.
    # Algorithm taken from Crypto.PublicKey.ElGamal.generate
    # TODO Should we use a generator of a subgroup for performance?
    if progress:
        progress('g', None)
    l.debug('Searching for a suitable generator g')
    start_time = time.time()
    q = (p - 1) / 2
    while True:
        g = gmpy.mpz(number.getRandomRange(3, p))
        if (pow(g, 2, p) == 1 or pow(g, q, p) == 1 or divmod(p-1, g)[1] == 0):
            continue
        ginv = gmpy.invert(g, p)
        if divmod(p - 1, ginv)[1] == 0:
            continue
        break
    l.debug('Found one in %.2fs', time.time() - start_time)
    return group_parameters(p=p, g=g)
