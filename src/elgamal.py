""" Extensions to pycrypto's implementation of ElGamal. """

import math
import time
import logging
import binascii
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
        128:  0.01499972,
        256:  0.00746354,
        512:  0.00372540,
        1024: 0.00185757,
        2048: 0.00094085 }
twin_primes_constant = 0.66016181584686961514307768084108829498291015625
asymptotic_safe_prime_density = 2 * twin_primes_constant / math.log(2)

# For debugging it is convenient to use precomputed group parameters.
PRECOMPUTED_GROUP_PARAMS = {
        1024: [
            '3b92900d4eab8b5e92b0516ab02ff5bee83bf0383b36121ff3b1da8a6e492519e'+
            'e4d4f1218f9ad322532f4366c3a5c86769d8c261155442f70f89dd1098f2d7f35'+
            '0e1fc68d7086cdb884d5bf7c4e1bdb1cf314343acf4032c9c4672b18b138bffe9'+
            'cc48f67052d0ec29b41a0a88aa287f9ca84906a7bdff2ace9c008936460a700',
            '74bc65768695b1fa536adc17dd9b6190b1c6411280543757dd05ec95e15e33ced'+
            '730e4f64cd182cb3fdc7d3c49db3fafdc2353dc67cf7ad90be0ba24e2ca3b6b40'+
            'eeab88f804eb345cf0173020ee1c722405f31840d9afbaed9e65102bcfead00f3'+
            '6479012635b1666d05a1b9beb4becc90d7a82dfd1e97807b7ed1d91d78929'],
        2048: [
            'aba1287059699f87089840bea5d1d88fbfd2c919f3c88f30a90aadd1cd3f27c55'+
            'c6abc7a8cb1bf73f6c06ce8ab1e0c1b26ac8dc98fcf22714d079ad7c92a01925f'+
            'abdce2f7a5a9298fc4ea27b247eb2ab63fa1dcbd23a12824c083bdb099e54bd0d'+
            '0c18171c84fbd435d192b5a756aa1a3622109da1c24a438c15fc622b08b16b7e2'+
            '99911fa5f5ac13255c41337f5098d722c8c48bccbf711ecf08f34c4161831ae01'+
            'f739a5755cee28f0bcd424cd603c9ed14d13bf3b2b3b12aa4a34d97404ea4bd68'+
            '99efb51cf95f3753ff98f9776cd75feb2516d1679aa512791c554c81ff19837b7'+
            'ddadddca411103ee8fab3bb54079011f024f71279b5708b3072a25e8700',
            '1aba2712ef86a010533977821c0156e13db37c770aa173d3c3052d258d1e0e0f6'+
            'be483515a68df10be550054b11da2ae3c0295938d2362eefd75ec050ba2aaae2d'+
            '248bf47f5e17cdf3094e50a7b10171744453391b06e3c355d4000f8f5178bca6b'+
            'ec94fc186fa03407fbb5f3c500960d00b57b1924b0355cc8f0ae386377ec1fe35'+
            '20ce3d23810ce4323ab90ce0cbeeff23ea317c62e75af3cda1d4b791f7c53ad57'+
            '4e7b8079427420b70b2fea107379e6c4b0012d2641a8edecb6306d63aecb5eb82'+
            'b993de1b003d4849e5f1a6b91de9a86a16e019b984fe8553cf6429a60a52351e5'+
            '5915c389ffc25c4979c3da26597882d51d5298b6ae981947c8f58f763']
        }

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

def precomputed_group_params(bits=1024):
    """ Return precomputed group parameters.

        NOTE For small group parameters this is unsafe. """
    if not bits in PRECOMPUTED_GROUP_PARAMS:
        raise ValueError("No precomputed group parameters of %s bits" % bits)
    p, g = [gmpy.mpz(binascii.unhexlify(x), 256)
                for x in PRECOMPUTED_GROUP_PARAMS[bits]]
    return group_parameters(p=p, g=g)

def generate_group_params(bits=1024, nthreads=None, progress=None):
    """ Generates group parameters for ElGamal. """
    # Find a safe prime as modulus.  This will take at least several
    # seconds on a single core.  Thus: we will parallelize.
    start_time = time.time()
    if nthreads is None:
        nthreads = multiprocessing.cpu_count()
    l.debug('Searching for a %s bit safe prime p as modulus on %s threads',
                bits, nthreads)
    safe_prime_density = SAFE_PRIME_DENSITY.get(bits,
                asymptotic_safe_prime_density / (bits - 1))
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
