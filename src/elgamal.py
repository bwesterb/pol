""" Extensions to pycrypto's implementation of ElGamal. """

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

group_parameters = collections.namedtuple('group_parameters', ('p', 'g'))

l = logging.getLogger(__name__)

if not number._fastmath:
    l.warning("pycrypto not built with _fastmath module.  A lot will be quite "+
              "slow")

def _find_safe_prime(bits=1024):
    """ Finds a safe prime of `bits` bits """
    randfunc = Crypto.Random.new().read
    q = gmpy.mpz(number.getRandomNBitInteger(bits-1, randfunc))
    while True:
        q = gmpy.next_prime(q)
        p = 2*q+1
        if gmpy.is_prime(p):
            return p

def generate_group_params(bits=1024, nthreads=None):
    """ Generates group parameters for ElGamal. """
    # Find a safe prime as modulus.  This will take at least several
    # seconds on a single core.  Thus: we will parallelize.
    if not nthreads:
        nthreads = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(nthreads, Crypto.Random.atfork)
    start_time = time.time()
    l.debug('Searching for a %s bit safe prime p as modulus on %s threads',
                bits, nthreads)
    done_event = threading.Event()
    _p = [None]
    def done(result):
        l.debug('Found one in %.2fs', time.time() - start_time)
        _p[0] = result
        done_event.set()
    for i in xrange(nthreads):
        pool.apply_async(_find_safe_prime, (bits,), {}, done)
    done_event.wait()
    pool.terminate()

    # Find a safe `g` as generator.
    # Algorithm taken from Crypto.PublicKey.ElGamal.generate
    # TODO Should we use a generator of a subgroup for performance?
    l.debug('Searching for a suitable generator g')
    start_time = time.time()
    p = _p[0]
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
