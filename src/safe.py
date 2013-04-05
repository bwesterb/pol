""" Implementation of pol safes.  See `Safe`. """

import time
import struct
import logging
import os.path
import binascii
import contextlib
import collections
import multiprocessing

import pol.blockcipher
import pol.parallel
import pol.elgamal
import pol.ks
import pol.kd

import lockfile
import msgpack
import gmpy

# TODO Generating random numbers seems CPU-bound.  Does the default random
#      generator wait for a certain amount of entropy?
import Crypto.Random
import Crypto.Random.random as random

l = logging.getLogger(__name__)

class MissingKey(ValueError):
    pass

class WrongKeyError(ValueError):
    pass

class SafeNotFoundError(ValueError):
    pass

class SafeFullError(ValueError):
    pass

class SafeFormatError(ValueError):
    pass

class SafeLocked(ValueError):
    pass

class SafeAlreadyExistsError(ValueError):
    pass

@contextlib.contextmanager
def create(path, override=False, *args, **kwargs):
    """ Generates a new safe.

        Contrary to `Safe.generate', this function also takes care
        of locking. """
    locked = False
    try:
        lock = lockfile.FileLock(path)
        lock.acquire(0)
        locked = True
        if os.path.exists(path) and not override:
            raise SafeAlreadyExistsError
        with _builtin_open(path, 'w') as f:
            safe = Safe.generate(*args, **kwargs)
            yield safe
            safe.store_to_stream(f)
    except lockfile.AlreadyLocked:
        raise SafeLocked
    finally:
        if locked:
            lock.release()

_builtin_open = open

@contextlib.contextmanager
def open(path, readonly=False, progress=None):
    """ Loads a safe from the filesystem.

        Contrary to `Safe.load_from_stream', this function also takes care
        of locking. """
    # TODO Allow multiple readers.
    locked = False
    try:
        lock = lockfile.FileLock(path)
        lock.acquire(0)
        locked = True
        if not os.path.exists(path):
            raise SafeNotFoundError
        with _builtin_open(path, 'r' if readonly else 'r+') as f:
            safe = Safe.load_from_stream(f)
            yield safe
            if not readonly and safe.touched:
                safe.rerandomize(progress=progress)
                f.seek(0, 0)
                f.truncate()
                safe.store_to_stream(f)
    except lockfile.AlreadyLocked:
        raise SafeLocked
    finally:
        if locked:
            lock.release()

class Safe(object):
    """ A pol safe deniably stores containers. (Containers store secrets.) """

    def __init__(self, data):
        self.data = data
        if 'key-stretching' not in self.data:
            raise SafeFormatError("Missing `key-stretching' attribute")
        if 'key-derivation' not in self.data:
            raise SafeFormatError("Missing `key-derivation' attribute")
        if 'block-cipher' not in self.data:
            raise SafeFormatError("Missing `block-cipher' attribute")
        self.ks = pol.ks.KeyStretching.setup(self.data['key-stretching'])
        self.kd = pol.kd.KeyDerivation.setup(self.data['key-derivation'])
        self.cipher = pol.blockcipher.BlockCipher.setup(
                            self.data['block-cipher'])
        self._touched = False

    def store_to_stream(self, stream):
        """ Stores the Safe to `stream'.

            This is done automatically if opened with `open'. """
        start_time = time.time()
        l.debug('Packing ...')
        msgpack.pack(self.data, stream)
        l.debug(' packed in %.2fs', time.time() - start_time)

    @staticmethod
    def load_from_stream(stream):
        """ Loads a Safe form a `stream'.

            If you load from a file, use `open' for that function also
            handles locking. """
        start_time = time.time()
        l.debug('Unpacking ...')
        data = msgpack.unpack(stream, use_list=True)
        l.debug(' unpacked in %.2fs', time.time() - start_time)
        if ('type' not in data or not isinstance(data['type'], basestring)
                or data['type'] not in TYPE_MAP):
            raise SafeFormatError("Invalid `type' attribute")
        return TYPE_MAP[data['type']](data)

    @staticmethod
    def generate(typ='elgamal', *args, **kwargs):
        if typ not in TYPE_MAP:
            raise ValueError("I do not know Safe type %s" % typ)
        return TYPE_MAP[typ].generate(*args, **kwargs)

    def new_container(self, password, list_password=None, append_password=None):
        """ Create a new container. """
        raise NotImplementedError

    def open_containers(self, password):
        """ Opens a container. """
        raise NotImplementedError

    def rerandomize(self):
        """ Rerandomizes the safe. """
        raise NotImplementedError

    def trash_freespace(self):
        """ Writes random data to the free space """
        raise NotImplementedError

    @property
    def touched(self):
        """ True when the Safe has been changed. """
        return self._touched

    def touch(self):
        self._touched = True

class Container(object):
    """ Containers store secrets. """
    def list(self):
        """ returns a list of all keys of all entries in this container """
        raise NotImplementedError
    def add(self, key, note, secret):
        """ adds a new entry (key, note, secret) """
        raise NotImplementedError
    def get(self, key):
        """ Returns (note, secret) for the entry with key `key' """
        raise NotImplementedError
    def save(self):
        """ Saves the changes made to the container to the safe. """
        raise NotImplementedError
    @property
    def can_add(self):
        raise NotImplementedError
    @property
    def id(self):
        """ An identifier for the container. """
        raise NotImplementedError

# Types used by ElGamalSafe
access_tuple = collections.namedtuple('access_tuple',
                        ('magic', 'type', 'key', 'index'))
append_tuple = collections.namedtuple('append_tuple',
                        ('magic', 'pubkey', 'entries'))
main_tuple = collections.namedtuple('main_tuple',
                        ('magic', 'append_index', 'entries', 'iv', 'secrets'))
secret_tuple = collections.namedtuple('secret_tuple',
                        ('privkey', 'entries'))

# Constants used for access slices
AS_MAGIC = binascii.unhexlify('1a1a8ad7')  # starting bytes of an access slice
AS_FULL = 0         # the access slice gives full access
AS_LIST = 1         # the access slice gives list-only access
AS_APPEND = 2       # the access slice gives append-only access

MAIN_SLICE_MAGIC = binascii.unhexlify('33653efc')
APPEND_SLICE_MAGIC = binascii.unhexlify('2d5039ba')

# We derive multiple keys from one base key using hashing and
# constants. For instance, given a base key K, the ElGamal private
# key for of the n-th block is KeyDerivation(K, KD_ELGAMAL, n)
KD_ELGAMAL = binascii.unhexlify('d53d376a7db498956d7d7f5e570509d5')
KD_MARKER  = binascii.unhexlify('7884002aaa175df1b13724aa2b58682a')
KD_SYMM    = binascii.unhexlify('4110252b740b03c53b1c11d6373743fb')
KD_LIST    = binascii.unhexlify('d53d376a7db498956d7d7f5e570509d5')
KD_APPEND  = binascii.unhexlify('76001c344cbd9e73a6b5bd48b67266d9')


class ElGamalSafe(Safe):
    """ Default implementation using rerandomization of ElGamal. """

    class Container(Container):
        def __init__(self, safe, full_key, list_key, append_key, main_slice,
                        append_slice, main_data, append_data, secret_data):
            self.safe = safe
            self.full_key = full_key
            self.list_key = list_key
            self.append_key = append_key
            self.main_slice = main_slice
            self.append_slice = append_slice
            self.main_data = main_data
            self.append_data = append_data
            self.secret_data = secret_data
        def save(self, randfunc=None, annex=False):
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            # Update secrets ciphertext
            if self.secret_data:
                assert self.full_key and self.main_data
                sbs = self.safe.cipher.blocksize
                iv = randfunc(sbs)
                cipherstream = self.safe._cipherstream(self.full_key, iv)
                secrets_pt = msgpack.dumps(self.secret_data)
                if len(secrets_pt) % sbs != 0:
                    padding = sbs - (len(secrets_pt) % sbs)
                    secrets_pt += '\0'*padding
                secrets_ct = cipherstream.encrypt(secrets_pt)
                self.main_data = self.main_data._replace(iv=iv,
                                        secrets=secrets_ct)
            # Write main slice
            if self.main_data:
                assert self.list_key and self.main_slice
                main_pt = msgpack.dumps(self.main_data)
                self.main_slice.store(self.list_key, main_pt, annex=annex)
            # Write append slice
            if self.append_data:
                assert self.append_key and self.append_slice
                append_pt = msgpack.dumps(self.append_data)
                self.append_slice.store(self.append_key, append_pt, annex=annex)
        def list(self):
            if self.main_data:
                return self.main_data.entries
            raise MissingKey
        def get(self, key):
            if self.main_data:
                for i, entry in enumerate(self.main_data.entries):
                    if entry[0] != key:
                        continue
                    if self.secret_data:
                        yield (entry[0], entry[1], self.secret_data.entries[i])
                    else:
                        yield (entry[0], entry[1])
            raise MissingKey
        def add(self, key, note, secret):
            # TODO implement append without full access
            if not self.secret_data:
                raise MissingKey
            self.main_data.entries.append((key, note))
            self.secret_data.entries.append(secret)
        @property
        def can_add(self):
            return bool(self.secret_data)
        @property
        def id(self):
            return (self.append_slice.first_index if self.append_slice else
                            self.main_slice.first_index)

    class Slice(object):
        def __init__(self, safe, first_index, indices, value=None):
            self.safe = safe
            self.indices = indices
            self.first_index = first_index
            self._value = value
        def trash(self, randfunc=None):
            """ Destroy contents of this slice by writing random values. """
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            # Generate a key, annex the blocks and store random data.
            key = randfunc(self.safe.kd.size)
            pt = randfunc(self.size)
            self.store(key, pt, randfunc, annex=True)
        @property
        def size(self):
            """ The amount of plaintext bytes this slice can store. """
            return (len(self.indices) * (self.safe.bytes_per_block
                                            - self.safe.block_index_size)
                        - 2*self.safe.cipher.blocksize - self.safe.slice_size)

        @property
        def value(self):
            return self._value

        def store(self, key, value, randfunc=None, annex=False):
            """ Stores `value' in the slice """
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            bpb = self.safe.bytes_per_block
            # First, get the full length plaintext string
            total_size = self.size
            if len(value) > total_size:
                raise ValueError("`value' too large")
            l.debug('Slice.store: storing @%s; %s blocks; %s/%sB',
                    self.first_index, len(self.indices), len(value),
                    total_size)
            raw = value.ljust(total_size, '\0')
            # Secondly, generate an IV, shuffle indices and get a cipherstream
            iv = randfunc(self.safe.cipher.blocksize)
            other_indices = list(self.indices)
            other_indices.remove(self.first_index)
            random.shuffle(other_indices)
            cipher = self.safe._cipherstream(key, iv)
            # Thirdly, write the first block
            first_block_pt_size = (bpb - 2*self.safe.cipher.blocksize
                                        - self.safe.block_index_size
                                        - self.safe.slice_size)
            if other_indices:
                second_block = other_indices[0]
            else:
                second_block = self.first_index
            first_block_ct = (self.safe.kd([self.safe._cipherstream_key(key)],
                                        length=self.safe.cipher.blocksize) + iv
                                + cipher.encrypt(self.safe._slice_size_to_bytes(
                                        len(value))+raw[:first_block_pt_size]
                                + self.safe._index_to_bytes(second_block)))
            self.safe._eg_encrypt_block(key, self.first_index, first_block_ct,
                                            randfunc, annex=annex)
            offset = first_block_pt_size
            ptsize = bpb - self.safe.block_index_size
            # Finally, write the remaining blocks
            for indexindex, index in enumerate(other_indices):
                if indexindex + 1 < len(other_indices):
                    next_index = other_indices[indexindex + 1]
                else:
                    next_index = index
                ct = cipher.encrypt(raw[offset:offset+ptsize] +
                                self.safe._index_to_bytes(next_index))
                offset += ptsize
                self.safe._eg_encrypt_block(key, index, ct, randfunc,
                                                annex=annex)
            self._value = value
            self.safe.touch()

    def __init__(self, data):
        super(ElGamalSafe, self).__init__(data)
        # Check if `data' makes sense.
        self.free_blocks = set([])
        for attr in ('group-params', 'n-blocks', 'blocks', 'block-index-size',
                            'slice-size'):
            if not attr in data:
                raise SafeFormatError("Missing attr `%s'" % attr)
        for attr, _type in {'blocks': list,
                            'group-params': list,
                            'block-index-size': int,
                            'slice-size': int,
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
        if data['slice-size'] == 2:
            self._slice_size_struct = struct.Struct('>H')
        elif data['slice-size'] == 4:
            self._slice_size_struct = struct.Struct('>I')
        else:
            raise SafeFormatError("`slice-size' invalid")
        if data['block-index-size'] == 1:
            self._block_index_struct = struct.Struct('>B')
        elif data['block-index-size'] == 2:
            self._block_index_struct = struct.Struct('>H')
        elif data['block-index-size'] == 4:
            self._block_index_struct = struct.Struct('>I')
        else:
            raise SafeFormatError("`block-index-size' invalid")
        if 2** (data['bytes-per-block']*8) >= self.group_params.p:
            raise SafeFormatError("`bytes-per-block' larger than "+
                                  "`group-params' allow")
    @staticmethod
    def generate(n_blocks=1024, block_index_size=2, slice_size=4,
                    ks=None, kd=None, blockcipher=None, gp_bits=1025,
                    precomputed_gp=False, nworkers=None, use_threads=False,
                    progress=None):
        """ Creates a new safe. """
        # TODO check whether block_index_size, slice_size, gp_bits and
        #      n_blocks are sane.
        # First, set the defaults
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
        if blockcipher is None:
            cipher = pol.blockcipher.BlockCipher.setup()
        # Now, calculate the useful bytes per block
        bytes_per_block = (gp_bits - 1) / 8
        bytes_per_block = bytes_per_block - bytes_per_block % cipher.blocksize
        # Initialize the safe object
        safe = ElGamalSafe(
                {'type': 'elgamal',
                 'n-blocks': n_blocks,
                 'bytes-per-block': bytes_per_block,
                 'block-index-size': block_index_size,
                 'slice-size': slice_size,
                 'group-params': [x.binary() for x in gp],
                 'key-stretching': ks.params,
                 'key-derivation': kd.params,
                 'block-cipher': cipher.params,
                 'blocks': [['','','',''] for i in xrange(n_blocks)]})
        # Mark all blocks as free
        safe.mark_free(xrange(n_blocks))
        return safe

    def open_containers(self, password):
        """ Opens a container. """
        l.debug('open_containers: Stretching key')
        access_key = self.ks(password)
        l.debug('open_containers: Searching for access slice ...')
        for sl in self._find_slices(access_key):
            access_data = access_tuple(*msgpack.loads(sl.value))
            if access_data.magic != AS_MAGIC:
                l.warn('Wrong magic on access slice')
                continue
            l.debug('open_containers:  found one @%s; type %s',
                            sl.first_index, access_data.type)
            yield self._open_container_with_access_data(access_data)

    def _open_container_with_access_data(self, access_data):
        (full_key, list_key, append_key, main_slice, append_slice, main_data,
                append_data, secret_data, append_index, main_index) = (None,
                        None, None, None, None, None, None, None, None, None)
        if access_data.type == AS_APPEND:
            append_key = access_data.key
            append_index = access_data.index
        elif access_data.type == AS_LIST:
            list_key = access_data.key
            main_index = access_data.index
        elif access_data.type == AS_FULL:
            full_key = access_data.key
            main_index = access_data.index
        else:
            raise SafeFormatError("Unknown slice type `%s'"
                                        % repr(access_data.type))
        if full_key:
            list_key = self.kd([full_key, KD_LIST])
        if list_key:
            main_slice = self._load_slice(list_key, main_index)
            main_data = main_tuple(*msgpack.loads(main_slice.value))
            append_key = self.kd([list_key, KD_APPEND])
            append_index = main_data.append_index
        if full_key:
            cipherstream = self._cipherstream(full_key, main_data.iv)
            secret_data = secret_tuple(*_msgpack_loads_padded(
                            cipherstream.decrypt(main_data.secrets)))
        if append_index:
            append_slice = self._load_slice(append_key, append_index)
            append_data = append_tuple(*msgpack.loads(append_slice.value))
        return ElGamalSafe.Container(self, full_key, list_key, append_key,
                    main_slice, append_slice, main_data, append_data,
                    secret_data)

    def new_container(self, password, list_password=None, append_password=None,
                                nblocks=170, randfunc=None):
        """ Create a new container. """
        # TODO support access blocks of more than one block in size.
        # TODO check append_slice_size makes sense
        append_slice_size = 5
        append_slice, append_data = None, None
        if randfunc is None:
            randfunc = Crypto.Random.new().read
        if len(self.free_blocks) < nblocks:
            raise SafeFullError
        # Divide blocks
        nblocks_mainslice = nblocks - 1
        if list_password:
            nblocks_mainslice -= 1
        if append_password:
            nblocks_mainslice -= 1 + append_slice_size
        # Create slices
        main_slice = self._new_slice(nblocks_mainslice)
        as_full = self._new_slice(1)
        if append_password or list_password:
            append_slice = self._new_slice(append_slice_size)
        if append_password:
            as_append = self._new_slice(1)
        if list_password:
            as_list = self._new_slice(1)
        # Generate the keys of the container
        l.debug('new_container: deriving keys')
        full_key = randfunc(self.kd.size)
        list_key = self.kd([full_key, KD_LIST])
        append_key = self.kd([list_key, KD_APPEND])
        # Derive keys from passwords
        as_full_key = self.ks(password)
        if append_password:
            as_append_key = self.ks(append_password)
        if list_password:
            as_list_key = self.ks(list_password)
        # Create access slices
        l.debug('new_container: creating access slices')
        as_full.store(as_full_key, msgpack.dumps(
                    access_tuple(magic=AS_MAGIC,
                                 type=AS_FULL,
                                 index=main_slice.first_index,
                                 key=full_key)), annex=True)
        if append_password:
            as_append.store(as_append_key, msgpack.dumps(
                    access_tuple(magic=AS_MAGIC,
                                 type=AS_APPEND,
                                 index=append_slice.first_index,
                                 key=append_key)), annex=True)
        if list_password:
            as_list.store(as_list_key, msgpack.dumps(
                    access_tuple(magic=AS_MAGIC,
                                 type=AS_LIST,
                                 index=main_slice.first_index,
                                 key=list_key)), annex=True)
        # Initialize main and append slices
        if append_slice:
            append_data = append_tuple(magic=APPEND_SLICE_MAGIC,
                                 pubkey=None, # TODO
                                 entries=[])
        main_data = main_tuple(magic=MAIN_SLICE_MAGIC,
                               append_index=(append_slice.first_index
                                                if append_slice else None),
                               entries=[],
                               iv=None,
                               secrets=None)
        secret_data = secret_tuple(privkey=None, # TODO
                                   entries=[])
        container =  ElGamalSafe.Container(self, full_key, list_key, append_key,
                        main_slice, append_slice, main_data, append_data,
                        secret_data)
        l.debug('new_container: saving')
        container.save(randfunc=randfunc, annex=True)
        return container

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
    def slice_size(self):
        """ The size of the sizefield of a slice.
            Thus actually: slice_size_size """
        return self.data['slice-size']

    @property
    def group_params(self):
        """ The group parameters. """
        return pol.elgamal.group_parameters(
                    *[gmpy.mpz(x, 256) for x in self.data['group-params']])

    def mark_free(self, indices):
        """ Marks the given indices as free. """
        self.free_blocks.update(indices)

    def trash_freespace(self):
        if not self.free_blocks:
            return
        l.debug('trash_freespace: trashing')
        sl = self._new_slice(len(self.free_blocks))
        sl.trash()

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

    def _new_slice(self, nblocks):
        """ Allocates a new slice with `nblocks' space. """
        if len(self.free_blocks) < nblocks:
            raise SafeFullError
        if nblocks == 0:
            raise ValueError("`nblocks' should be positive")
        free_blocks = list(self.free_blocks)
        random.shuffle(free_blocks)
        indices = free_blocks[:nblocks]
        self.free_blocks = set(free_blocks[nblocks:])
        ret = ElGamalSafe.Slice(self, random.choice(indices), indices)
        return ret

    def _find_slices(self, key):
        """ Find slices that are opened by base key `key' """
        symmkey_hash = self.kd([self._cipherstream_key(key)],
                            length=self.cipher.blocksize)
        # TODO parallelize this
        for index in xrange(self.nblocks):
            try:
                pt = self._eg_decrypt_block(key, index)
            except WrongKeyError:
                continue
            # We got a block.  Is it the first block?
            if pt.startswith(symmkey_hash):
                yield self._load_slice_from_first_block(key, index, pt)

    def _load_slice(self, key, index):
        """ Loads the slice with first block `index' encrypted
            with base key `key' """
        fb = self._eg_decrypt_block(key, index)
        symmkey_hash = self.kd([self._cipherstream_key(key)],
                            length=self.cipher.blocksize)
        if not fb.startswith(symmkey_hash):
            raise WrongKeyError
        return self._load_slice_from_first_block(key, index, fb)

    def _load_slice_from_first_block(self, key, index, fbct):
        # First, extract the IV and create a cipherstream
        l.debug('_load_slice_from_first_block: @%s', index)
        indices = [index]
        iv = fbct[self.cipher.blocksize:self.cipher.blocksize*2]
        cipherstream = self._cipherstream(key, iv)
        # Now, read the first block
        fbpt = cipherstream.decrypt(fbct[self.cipher.blocksize*2:])
        size = self._slice_size_from_bytes(fbpt[:self.slice_size])
        ret = fbpt[self.slice_size:-self.block_index_size]
        current_index = index
        next_index = self._index_from_bytes(fbpt[-self.block_index_size:])
        # Finally, read the remaining blocks
        while current_index != next_index:
            current_index = next_index
            indices.append(current_index)
            ct = self._eg_decrypt_block(key, current_index)
            pt = cipherstream.decrypt(ct)
            ret += pt[:-self.block_index_size]
            next_index = self._index_from_bytes(pt[-self.block_index_size:])
        l.debug('_load_slice_from_first_block:   %s blocks', len(indices))
        return ElGamalSafe.Slice(self, index, indices, ret[:size])

    def _index_to_bytes(self, index):
        return self._block_index_struct.pack(index)
    def _index_from_bytes(self, s):
        return self._block_index_struct.unpack(s)[0]
    def _slice_size_to_bytes(self, size):
        return self._slice_size_struct.pack(size)
    def _slice_size_from_bytes(self, s):
        return self._slice_size_struct.unpack(s)[0]

    # TODO if we use a cipherstream in counter block mode, then we can
    #      slices on multiple cores.
    def _cipherstream_key(self, key):
        return self.kd([key, KD_SYMM], length=self.cipher.keysize)
    def _cipherstream(self, key, iv):
        """ Returns a blockcipher stream for key `key' """
        return self.cipher.new_stream(self._cipherstream_key(key), iv)
    def _marker_for_block(self, key, index):
        """ Returns the key used to mark a block at `index' as owned
            by `key' """
        # TODO make this faster with a secure RNG?
        return self.kd([key, KD_MARKER, self._index_to_bytes(index)])
    def _privkey_for_block(self, key, index):
        """ Returns the elgamal private key for the block `index' """
        # TODO we should not assume how mpz.binary() works
        # TODO is it safe to reduce the size of privkey by this much?
        return gmpy.mpz(self.kd([key, KD_ELGAMAL, self._index_to_bytes(index)],
                            length=self.bytes_per_block) + '\0', 256)

    # ElGamal encryption and decryption
    def _eg_decrypt_block(self, key, index):
        """ Decrypts the block `index' with `key' """
        marker = self._marker_for_block(key, index)
        if self.data['blocks'][index][3] != marker:
            raise WrongKeyError
        privkey = self._privkey_for_block(key, index)
        gp = self.group_params
        c1 = gmpy.mpz(self.data['blocks'][index][0], 256)
        c2 = gmpy.mpz(self.data['blocks'][index][1], 256)
        return pol.elgamal.decrypt(c1, c2, privkey, gp, self.bytes_per_block)
    def _eg_encrypt_block(self, key, index, s, randfunc, annex=False):
        """ Sets the El-Gamal encrypted content of block `index' to `s'
            using key `key' """
        assert len(s) <= self.bytes_per_block
        privkey = self._privkey_for_block(key, index)
        gp = self.group_params
        marker = self._marker_for_block(key, index)
        if self.data['blocks'][index][3] != marker:
            if not annex:
                raise WrongKeyError
            pubkey = pol.elgamal.pubkey_from_privkey(privkey, gp)
            binary_pubkey = pubkey.binary()
            self.data['blocks'][index][2] = binary_pubkey
            self.data['blocks'][index][3] = marker
        else:
            pubkey = gmpy.mpz(self.data['blocks'][index][2], 256)
        # TODO is it safe to pick r so much smaller than p?
        c1, c2 = pol.elgamal.encrypt(s, pubkey, gp,
                                     self.bytes_per_block, randfunc)
        self.data['blocks'][index][0] = c1.binary()
        self.data['blocks'][index][1] = c2.binary()

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

def _msgpack_loads_padded(s):
    """ The same as msgpack.loads, but does not raise an exception if
        unread data remains. """
    unpacker = msgpack.Unpacker()
    unpacker.feed(s)
    return unpacker.unpack()

TYPE_MAP = {'elgamal': ElGamalSafe}
