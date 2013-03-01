""" Implementation of pol safes.  See `Safe`. """

import time
import logging
import multiprocessing

import pol.elgamal

import msgpack
import gmpy2

import Crypto.Random
import Crypto.Random.random as random

l = logging.getLogger(__name__)

class SafeFormatError(ValueError):
    pass

class Safe(object):
    """ A pol safe deniably stores containers. (Containers store secrets.) """

    def __init__(self, data):
        self.data = data

    def store(self, stream):
        start_time = time.time()
        l.info('Packing ...')
        msgpack.pack(self.data, stream)
        l.info(' packed in %.2fs', time.time() - start_time)

    @staticmethod
    def load(stream):
        start_time = time.time()
        l.info('Unpacking ...')
        data = msgpack.unpack(stream, use_list=True)
        l.info(' unpacked in %.2fs', time.time() - start_time)
        if ('type' not in data or not isinstance(data['type'], basestring)
                or data['type'] not in TYPE_MAP):
            raise SafeFormatError("Invalid `type' attribute")
        return TYPE_MAP[data['type']](data)

    @staticmethod
    def generate(typ='elgamal', *args, **kwargs):
        if typ not in TYPE_MAP:
            raise ValueError("I do not know Safe type %s" % typ)
        return TYPE_MAP[typ].generate(*args, **kwargs)

class ElGamalSafe(Safe):
    """ Default implementation using rerandomization of ElGamal. """
    
    @staticmethod
    def generate(n_blocks=1024, block_index_size=2, nthreads=None):
        gp = pol.elgamal.generate_group_params(nthreads=nthreads)
        safe = Safe(
                {'type': 'elgamal',
                 'n-blocks': n_blocks,
                 'block-index-size': block_index_size,
                 'group-params': map(gmpy2.to_binary, gp),
                 'blocks': [[
                    # FIXME stub
                    gmpy2.to_binary(gmpy2.mpz(random.randint(2, int(gp.p)))),
                    gmpy2.to_binary(gmpy2.mpz(random.randint(2, int(gp.p)))),
                    gmpy2.to_binary(gmpy2.mpz(random.randint(2, int(gp.p))))
                            ]
                         for i in xrange(n_blocks)]})
        return safe

    @property
    def nblocks(self):
        """ Number of blocks. """
        return self.data['n-blocks']

    @property
    def group_params(self):
        """ The group parameters. """
        return pol.elgamal.group_parameters(
                    *map(gmpy2.from_binary, self.data['group-params']))
    
    def rerandomize(self, nthreads=None):
        """ Rerandomizes blocks: they will still decrypt to the same
            plaintext. """
        if not nthreads:
            nthreads = multiprocessing.cpu_count()
        l.debug("Rerandomizing %s blocks on %s threads ...",
                    self.nblocks, nthreads)
        pool = multiprocessing.Pool(nthreads, Crypto.Random.atfork)
        start_time = time.time()
        gp = self.group_params
        self.data['blocks'] = pool.map(_rerandomize_block,
                    [(gp.g, gp.p, b) for b in self.data['blocks']])
        secs = time.time() - start_time
        kbps = self.nblocks * gmpy2.num_digits(gp.p,2) / 1024.0 / 8.0 / secs
        l.debug(" done in %.2fs; that is %.2f KB/s", secs, kbps)

def _rerandomize_block(g_p_block):
    g, p, raw_b = g_p_block
    s = random.randint(2, int(p))
    b = map(gmpy2.from_binary, raw_b)
    b[0] = (b[0] * pow(g, s, p)) % p
    b[1] = (b[1] * pow(b[2], s, p)) % p
    return map(gmpy2.to_binary, b)

TYPE_MAP = {'elgamal': ElGamalSafe}
