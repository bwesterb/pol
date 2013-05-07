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
import demandimport
import Crypto.Util.number as number

import Crypto.Random

# gmpy
import gmpy

import pol.parallel
import pol.progressbar
import pol.serialization

group_parameters = collections.namedtuple('group_parameters', ('p', 'g'))

l = logging.getLogger(__name__)

# TODO add more explanation
twin_primes_constant = 0.66016181584686961514307768084108829498291015625
asymptotic_safe_prime_density = 2 * twin_primes_constant / math.log(2)

# For debugging it is convenient to use precomputed group parameters.
PRECOMPUTED_GROUP_PARAMS = {
        1025: [
            '737d5bc38a37bac243f563b199fb76ade9f954d7ae0f2343724812681f21f3be1'+
            'fd0c60ce8e05650174b5df9ca68bf039ae9af895137c2b25f875cd3e5a7645ac5'+
            '76ac9dbd5ac1fcc90d65e7524cb7a139f393280504f30af83b5d72a444d691f30'+
            'c2a385e4cfa6b3f18fd31de59b76ebbe5cae2781b438180d21a11839d7baa01',
            '72a7b36dc30de8d0c3807328d103ff04e2cf85978d7ff010fecbbdb98b1df39ce'+
            'a5e7b56dc337d62643bf3d51ad8fe2540344fe5cc7dd20f18afe07e1afe1cb034'+
            'feaffe659c761b4bb55dbf6eb202ffd1c66e7b2170fba4b97dc3053366c12fc71'+
            '39a6ef328d7309aec32bed82885afca3c0188efbb0a4d12b48edd82830c2c01'],
        2049: [
            '1f7b6c8b627fba64eb7811dbf3137f4c02f9f11968173c597d3c0ac8c8824e83d'+
            'eb55c34c409edad265a3f65aabcd665c12fb9b7fbffa052645a43cc2d0b6a1907'+
            'dc192ee7d2acf86157d878d29480c47adadfcfc43f7a779777ffb8e1c674c099b'+
            '20a6251fb4c2c3a597b003f5df0cb7e66ee69490d6379f577051b19e88b642b71'+
            '5fa51e5312fddd8c2b36f136b4b2976baa3a3970956a680c8bf9cf71fe6a60080'+
            '377592ae9b25a99eef0afde788ac2feb0b780daaf7873f14a7efc21596e388f88'+
            '9754480032f0a9faafd800d8b0752ca33033134aceec56cae58b7aab80e793032'+
            '8752d830be2d318edc9026f46031f0171f1cb53c02ab2f4bf9a8e5de401',
            '43dc9cb8ed75d53efe931f7fbb83ace5c0a37631cd5eb8bd3c420fb0bef3cc8a8'+
            'b29c3d59982e1f0e1f32e1a082dad03a44ec9cae3391c42d5b172e688386094c4'+
            'ec167f906c3ccaba9b904f6ec1de9cf176d72ec701a1d6f31c5117428997b1dc0'+
            '067b16bee2b05a91137f903fe10075e27dfb225d34c733d543782806fcf98dfb0'+
            'cf3c17b570e1b639df912d74174936b2dffe71b32ea11dbd14b1d9eb7558a902f'+
            '91c43d595b7e4373eff4bd9e389fe2b5cf833585434b25d9530a36f9d034e0d26'+
            '8254268dc5cddf8010aa2d6196b3d8c0a119f00fbdbff472adc3016f27c5a7374'+
            '3b3c4f643a1990882a3224992cce2fe4c3b418dcb3676f4fdf8a5dade01'],
        4097: [
            '2f3df5a84baadc8725396d3788b5c3e022afe1f31717b4df811eca5fa9e672c68'+
            'e855d34e36d9c5b79ac7d323e3770ff028160bca584e8459b313d9217e17b11f9'+
            'b985a86b8ae04442b152408738e5954d98c52e44393791b503a58c774754ffd14'+
            'e83db62b706fac2472a4eb79c4d0014239247c8e1cecee023c5bf9a59239c5166'+
            '9a22bb9d8a374143323602354be85062615bbb8f1b7a3674cf27472d648f4613b'+
            'd59e0945197648452fd453bb32817dc6b221577996b86b0f04f392516143742b7'+
            '245d926cf9ce154c0a1f45e1ac6d2ef20f64fb030897c489cc95eda047117c240'+
            'e39933d9afad273ff607a4b9f82e507af75dc66d37e2453927d67a8c0217ab243'+
            '28e8808801a06aab963a4574b70b7ae7fabf03271524dee6c70c836047641922f'+
            '1278aba60ce451948891e7e0b3e8fb06a21a10256371dd1c1aac1d95f3d745538'+
            '81f6af2a6dd3a70c1138171ca068af4d83f5952db172c8e6f89e8fba87a3ba241'+
            '8b34079d8053034aedaca662c713ed03dc35ce6e67c4385e09affed4e995e09c1'+
            'd4e7e0e932b4a1fd63ba6ae3920c0cb70af77d67c17f13bc63cb9688463eb6c53'+
            '05a4fcb063ab1ad828523c71af1b75c7f2462c4805d38ed648e5342e19c5c8d87'+
            '0c0e443526a9dbe130a03f8240b1682cb65c1999c8091b5f66217419d2b74d435'+
            '5ebc16900bd7fa2ffe4a566f2ef2bf15123de1669ab56c1eb01',
            'e7264b8afe53f07869ab06261d6a1cec13d34609a2ae47dd18a2b3817eb8ad681'+
            '46face0faebd90d6dcb57de81030d1c34a03308be80d2bfe0c8220088cb1329d7'+
            '9fec8f6ffe6c5dea39f04689a8aeb4c7173d7b159885ac83573e4b0c96fd1b638'+
            'a4e390ea6f8a24dc14d5db3ed22ded2bee234dd3a95156127bfcf56901de3c514'+
            '94dc501561c7af94c73d8fc0bfc8b7f99bb761ed44dc7acbbf5080b2c33b1b734'+
            'dc93832e789db5d4cbb7c6ce78c3b80fa0373145bf88fd05245d896a685fa3028'+
            '445d7239a9a533393f25256d37d5e68006d225a82cfc30b4a83dc17a67241e669'+
            'c37426f725a07a61a4cc1d44f3ffa47c12fd3a55bb624470f0946f2b5f09c7f4e'+
            '97251205f977d50945755b8ac459bd4b00635d3f7766a8443089dc9135d5acc1f'+
            'dddc3fd92c3891e7b455a468c5e721875326b0101864aaed38ecf14e0aebec0b4'+
            '457be9c09bc45139b8eaccafd9d2332f145a9c7d598b5e0e4e67a4632c9ad16e8'+
            'e54823c925d9c8876dc0f92ddaf2587e297fa2da2ed8c3231921d8384f889e210'+
            'ae3e511e0d67b5c4b48a7158f49b29528d32d85120edeef742a9cca5c3444b3b3'+
            '7410e51cb7118b97c9150ebbabc4b5747e364d3b705a2b9ecc01f4ed17f49df7a'+
            'b56d975e3f740c8bc7b77a708bdf86cf55d682c2ccc2afd7b7c57014d3599bac0'+
            '05523817cb087debb711289e28db4fd35da61ad6e4c39106e01']
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

def precomputed_group_params(bits=1025):
    """ Return precomputed group parameters.

        NOTE For small group parameters this is unsafe. """
    if not bits in PRECOMPUTED_GROUP_PARAMS:
        raise ValueError("No precomputed group parameters of %s bits" % bits)
    p, g = [pol.serialization.string_to_number(binascii.unhexlify(x))
                for x in PRECOMPUTED_GROUP_PARAMS[bits]]
    return group_parameters(p=p, g=g)

def generate_group_params(bits=1025, nworkers=None, use_threads=False,
                                progress=None):
    """ Generates group parameters for ElGamal. """
    # Find a safe prime as modulus.  This will take at least several
    # seconds on a single core.  Thus: we will parallelize.
    start_time = time.time()
    if nworkers is None:
        nworkers = multiprocessing.cpu_count()
    l.debug('Searching for a %s bit safe prime p as modulus on %s workers',
                bits, nworkers)
    safe_prime_density = asymptotic_safe_prime_density / (bits - 1)
    if progress:
        progress('p', None)
        def _progress(n):
            progress('p', pol.progressbar.coin(safe_prime_density, n))
    else:
        _progress = None
    p = pol.parallel.parallel_try(_find_safe_prime, (bits,),
                            initializer=_find_safe_prime_initializer,
                            progress=_progress, nworkers=nworkers,
                            use_threads=use_threads)
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

def pubkey_from_privkey(privkey, gp):
    return pow(gp.g, privkey, gp.p)
def string_to_group(s):
    return pol.serialization.string_to_number(s)
def group_to_string(n, size):
    # TODO is mpz.binary() stable?
    return pol.serialization.number_to_string(n).ljust(size, '\0')
def decrypt(c1, c2, privkey, gp, size):
    s = pow(c1, privkey, gp.p)
    invs = gmpy.invert(s, gp.p)
    return group_to_string((invs * c2) % gp.p, size)
def encrypt(string, pubkey, gp, size, randfunc):
    # TODO how small may size be?
    number = string_to_group(string)
    r = string_to_group(randfunc(size))
    c1 = pow(gp.g, r, gp.p)
    s = pow(pubkey, r, gp.p)
    c2 = (number * s) % gp.p
    return (c1, c2)
