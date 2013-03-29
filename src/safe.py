""" Implementation of pol safes.  See `Safe`. """

import time
import struct
import logging
import binascii
import multiprocessing

import pol.parallel
import pol.elgamal
import pol.ks
import pol.kd

import msgpack
import gmpy

# TODO Generating random numbers seems CPU-bound.  Does the default random
#      generator wait for a certain amount of entropy?
import Crypto.Random
import Crypto.Random.random as random

l = logging.getLogger(__name__)

# Constants used for access slices
AS_MAGIC = binascii.unhexlify('1a1a8ad7')  # starting bytes of an access slice
AS_FULL = 0         # the access slice gives full access
AS_LIST = 1         # the access slice gives list-only access
AS_APPEND = 2       # the access slice gives append-only access

# We derive multiple keys from one base key using hashing and
# constants. For instance, given a base key K, the ElGamal private
# key for of the n-th block is KeyDerivation(K, KD_ELGAMAL, n)
KD_ELGAMAL = binascii.unhexlify('d53d376a7db498956d7d7f5e570509d5')
KD_LIST = binascii.unhexlify('d53d376a7db498956d7d7f5e570509d5')
KD_APPEND = binascii.unhexlify('76001c344cbd9e73a6b5bd48b67266d9')

class SafeFormatError(ValueError):
    pass

class Safe(object):
    """ A pol safe deniably stores containers. (Containers store secrets.) """

    def __init__(self, data):
        self.data = data
        if 'key-stretching' not in self.data:
            raise SafeFormatError("Missing `key-stretching' attribute")
        if 'key-derivation' not in self.data:
            raise SafeFormatError("Missing `key-derivation' attribute")
        self.ks = pol.ks.KeyStretching.setup(self.data['key-stretching'])
        self.kd = pol.kd.KeyDerivation.setup(self.data['key-derivation'])

    def store(self, stream):
        start_time = time.time()
        l.info('Packing ...')
        msgpack.pack(self.data, stream)
        l.info(' packed in %.2fs', time.time() - start_time)

    def open(self, password):
        pass

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

    def __init__(self, data):
        super(ElGamalSafe, self).__init__(data)
        # Check if `data' makes sense.
        for attr in ('group-params', 'n-blocks', 'blocks', 'block-index-size'):
            if not attr in data:
                raise SafeFormatError("Missing attr `%s'" % attr)
        for attr, _type in {'blocks': list,
                            'group-params': list,
                            'block-index-size': int,
                            'bytes-per-block': int,
                            'n-blocks': int}.iteritems():
            if not isinstance(data[attr], _type):
                raise SafeFormatError("`%s' should be a `%s'" % (attr, _type))
        if not len(data['blocks']) == data['n-blocks']:
            raise SafeFormatError("Amount of blocks isn't `n-blocks'")
        if not len(data['group-params']) == 2:
            raise SafeFormatError("`group-params' should contain 2 elements")
        # TODO Should we check whether the group parameters are safe?
        for x in data['group-params']:
            if not isinstance(x, basestring):
                raise SafeFormatError("`group-params' should contain strings")
        if data['block-index-size'] == 1:
            self._block_index_struct = struct.Struct('>B')
        elif data['block-index-size'] == 4:
            self._block_index_struct = struct.Struct('>H')
        elif data['block-index-size'] == 4:
            self._block_index_struct = struct.Struct('>I')
        if 2** (data['bytes-per-block']*8) >= self.group_params.p:
            raise SafeFormatError("`bytes-per-block' larger than "+
                                  "`group-params' allow")
    @staticmethod
    def generate(n_blocks=1024, block_index_size=2, ks=None, kd=None,
                    gp_bits=1025, precomputed_gp=False,
                    nworkers=None, use_threads=False, progress=None):
        """ Creates a new safe. """
        if precomputed_gp:
            gp = pol.elgamal.precomputed_group_params(gp_bits)
        else:
            gp = pol.elgamal.generate_group_params(bits=gp_bits,
                    nworkers=nworkers, progress=progress,
                    use_threads=use_threads)
        if ks is None:
            ks = pol.ks.KeyStretching.setup()
        if kd is None:
            kd = pol.kd.KeyDerivation.setup()
        bytes_per_block = (gp_bits - 1) / 8
        safe = Safe(
                {'type': 'elgamal',
                 'n-blocks': n_blocks,
                 'bytes-per-block': bytes_per_block,
                 'block-index-size': block_index_size,
                 'group-params': [x.binary() for x in gp],
                 'key-stretching': ks.params,
                 'key-derivation': kd.params,
                 'blocks': [[
                    # FIXME stub
                    gmpy.mpz(random.randint(2, int(gp.p))).binary(),
                    gmpy.mpz(random.randint(2, int(gp.p))).binary(),
                    gmpy.mpz(random.randint(2, int(gp.p))).binary()
                            ]
                         for i in xrange(n_blocks)]})
        return safe

    @property
    def nblocks(self):
        """ Number of blocks. """
        return self.data['n-blocks']

    @property
    def bytes_per_block(self):
        """ Number of bytes stored per block. """
        return self.data['bytes-per-block']

    @property
    def block_index_size(self):
        """ Size of a block index. """
        return self.data['block-index-size']

    @property
    def group_params(self):
        """ The group parameters. """
        return pol.elgamal.group_parameters(
                    *[gmpy.mpz(x, 256) for x in self.data['group-params']])
    
    def rerandomize(self, nworkers=None, use_threads=False, progress=None):
        """ Rerandomizes blocks: they will still decrypt to the same
            plaintext. """
        _progress = None
        if progress is not None:
            def _progress(n):
                progress(float(n) / self.nblocks)
        if not nworkers:
            nworkers = multiprocessing.cpu_count()
        l.debug("Rerandomizing %s blocks on %s workers ...",
                    self.nblocks, nworkers)
        start_time = time.time()
        gp = self.group_params
        self.data['blocks'] = pol.parallel.parallel_map(_eg_rerandomize_block,
                        self.data['blocks'], args=(gp.g, gp.p),
                        nworkers=nworkers, use_threads=use_threads,
                        initializer=_eg_rerandomize_block_initializer,
                        chunk_size=16, progress=_progress)
        secs = time.time() - start_time
        kbps = self.nblocks * gmpy.numdigits(gp.p,2) / 1024.0 / 8.0 / secs
        if progress is not None:
            progress(1.0)
        l.debug(" done in %.2fs; that is %.2f KB/s", secs, kbps)

    def _index_to_bytes(self, index):
        self._block_index_struct.pack(index)
    def _index_from_bytes(self, s):
        self._block_index_struct.unpack(s)

    def _privkey_for_block(self, key, index):
        """ Returns the elgamal private key for the block `index' """
        return self.kd([key, KD_ELGAMAL, self._index_to_bytes(index)],
                            length=self.bytes_per_block)

def _eg_rerandomize_block_initializer(args, kwargs):
    Crypto.Random.atfork()
def _eg_rerandomize_block(raw_b, g, p):
    """ Rerandomizes raw_b given group parameters g and p. """
    s = random.randint(2, int(p))
    b = [gmpy.mpz(raw_b[0], 256),
         gmpy.mpz(raw_b[1], 256),
         gmpy.mpz(raw_b[2], 256)]
    b[0] = (b[0] * pow(g, s, p)) % p
    b[1] = (b[1] * pow(b[2], s, p)) % p
    raw_b[0] = b[0].binary()
    raw_b[1] = b[1].binary()
    return raw_b

TYPE_MAP = {'elgamal': ElGamalSafe}
