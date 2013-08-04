""" Implementation of pol safes.  See `Safe`. """

import time
import struct
import logging
import os.path
import binascii
import contextlib
import collections
import multiprocessing

import pol.serialization
import pol.blockcipher
import pol.parallel
import pol.envelope
import pol.xrandom
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

SAFE_MAGIC = 'pol\n' + binascii.unhexlify('d163d4977a2cf681ad9a6cfe98ab')

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

class WrongMagicError(SafeFormatError):
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
def open(path, readonly=False, progress=None, nworkers=None, use_threads=False,
                    always_rerandomize=True):
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
            safe = Safe.load_from_stream(f, nworkers, use_threads)
            yield safe
            if not readonly:
                safe.autosave_containers()
                if safe.touched or always_rerandomize:
                    safe.rerandomize(progress=progress,
                                     nworkers=nworkers,
                                     use_threads=use_threads)
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

    def __init__(self, data, nworkers, use_threads):
        self.data = data
        self.nworkers = nworkers
        self.use_threads = use_threads
        if 'key-stretching' not in self.data:
            raise SafeFormatError("Missing `key-stretching' attribute")
        if 'key-derivation' not in self.data:
            raise SafeFormatError("Missing `key-derivation' attribute")
        if 'block-cipher' not in self.data:
            raise SafeFormatError("Missing `block-cipher' attribute")
        if 'envelope' not in self.data:
            raise SafeFormatError("Missing `envelope' attribute")
        self.ks = pol.ks.KeyStretching.setup(self.data['key-stretching'])
        self.kd = pol.kd.KeyDerivation.setup(self.data['key-derivation'])
        self.envelope = pol.envelope.Envelope.setup(self.data['envelope'])
        self.cipher = pol.blockcipher.BlockCipher.setup(
                            self.data['block-cipher'])
        self._touched = False

    def store_to_stream(self, stream):
        """ Stores the Safe to `stream'.

            This is done automatically if opened with `open'. """
        start_time = time.time()
        l.debug('Packing ...')
        stream.write(SAFE_MAGIC)
        msgpack.pack(self.data, stream)
        l.debug(' packed in %.2fs', time.time() - start_time)

    @staticmethod
    def load_from_stream(stream, nworkers, use_threads):
        """ Loads a Safe form a `stream'.

            If you load from a file, use `open' for that function also
            handles locking. """
        start_time = time.time()
        l.debug('Unpacking ...')
        magic = stream.read(len(SAFE_MAGIC))
        if magic != SAFE_MAGIC:
            raise WrongMagicError
        data = msgpack.unpack(stream, use_list=True)
        l.debug(' unpacked in %.2fs', time.time() - start_time)
        if ('type' not in data or not isinstance(data['type'], basestring)
                or data['type'] not in TYPE_MAP):
            raise SafeFormatError("Invalid `type' attribute")
        return TYPE_MAP[data['type']](data, nworkers, use_threads)

    @staticmethod
    def generate(typ='elgamal', *args, **kwargs):
        if typ not in TYPE_MAP:
            raise ValueError("I do not know Safe type %s" % typ)
        return TYPE_MAP[typ].generate(*args, **kwargs)

    def new_container(self, password, list_password=None, append_password=None):
        """ Create a new container. """
        raise NotImplementedError

    def open_containers(self, password, additional_keys=[]):
        """ Opens a container. """
        raise NotImplementedError

    def rerandomize(self):
        """ Rerandomizes the safe. """
        raise NotImplementedError

    def trash_freespace(self):
        """ Writes random data to the free space """
        raise NotImplementedError

    def autosave_containers(self):
        """ Autosave containers """
        pass

    @property
    def touched(self):
        """ True when the Safe has been changed. """
        return self._touched

    def touch(self):
        self._touched = True

class Entry(object):
    """ An entry of a container """
    @property
    def key(self):
        raise NotImplementedError
    @property
    def has_secret(self):
        raise NotImplementedError
    @property
    def secret(self):
        raise NotImplementedError
    @property
    def note(self):
        raise NotImplementedError
    def remove(self):
        raise NotImplementedError

class Container(object):
    """ Containers store secrets. """
    def list(self):
        """ Returns the entries of the container. """
        raise NotImplementedError
    def add(self, key, note, secret):
        """ adds a new entry (key, note, secret) """
        raise NotImplementedError
    def get(self, key):
        """ Returns the entries with key `key' """
        raise NotImplementedError
    def save(self):
        """ Saves the changes made to the container to the safe. """
        raise NotImplementedError
    @property
    def can_add(self):
        raise NotImplementedError
    @property
    def has_secrets(self):
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

    class MainEntry(Entry):
        def __init__(self, container, index):
            self.container = container
            self.index = index

        def _get_key(self):
            return self.container.main_data.entries[self.index][0]
        def _set_key(self, new_key):
            self.container.main_data.entries[self.index][0] = new_key
            self.container.unsaved_changes = True
        key = property(_get_key, _set_key)

        def _get_note(self):
            return self.container.main_data.entries[self.index][1]
        def _set_note(self, new_note):
            self.container.main_data.entries[self.index][1] = new_note
            self.container.unsaved_changes = True
        note = property(_get_note, _set_note)

        def _get_secret(self):
            if self.container.secret_data is None:
                raise MissingKey
            return self.container.secret_data.entries[self.index]
        def _set_secret(self, new_secret):
            if self.container.secret_data is None:
                raise MissingKey
            self.container.secret_data.entries[self.index] = new_secret
            self.container.unsaved_changes = True
        secret = property(_get_secret, _set_secret)

        def remove(self):
            if self.container.secret_data is None:
                raise MissingKey
            self.container.secret_data.entries[self.index] = None
            self.container.main_data.entries[self.index] = None
            self.container.unsaved_changes = True

        @property
        def has_secret(self):
            return self.container.secret_data is not None

    class AppendEntry(Entry):
        def __init__(self, container, index, key, note, secret):
            self.container = container
            self.index = index
            self._key = key
            self._note = note
            self._secret = secret

        def _ensure_update_entry_exists(self):
            if self.index not in self.container.append_data_updates:
                self.container.append_data_updates[self.index] = [self._key,
                                                                  self._note,
                                                                  self._secret]
        def _get_key(self):
            return self._key
        def _set_key(self, new_key):
            self._ensure_update_entry_exists()
            self.container.append_data_updates[self.index][0] = new_key
            self.container.unsaved_changes = True
        key = property(_get_key, _set_key)

        def _get_note(self):
            return self._note
        def _set_note(self, new_note):
            self._ensure_update_entry_exists()
            self.container.append_data_updates[self.index][1] = new_note
            self.container.unsaved_changes = True
        note = property(_get_note, _set_note)

        def _get_secret(self):
            return self._secret
        def _set_secret(self, new_secret):
            self._ensure_update_entry_exists()
            self.container.append_data_updates[self.index][2] = new_secret
            self.container.unsaved_changes = True
        secret = property(_get_secret, _set_secret)

        def remove(self):
            self._ensure_update_entry_exists()
            self.container.append_data_updates[self.index] = None
            self.container.unsaved_changes = True

        @property
        def has_secret(self):
            return True

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
            self.append_data_updates = {}
            self.unsaved_changes = False

        def save(self, randfunc=None, annex=False):
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            # Update secrets ciphertext
            if self.secret_data:
                assert self.full_key and self.main_data
                sbs = self.safe.cipher.blocksize
                iv = randfunc(sbs)
                cipherstream = self.safe._cipherstream(self.full_key, iv)
                # Filter entries that are marked for deletion
                secret_data = self.secret_data._replace(
                        entries=filter(lambda x: x is not None,
                                        self.secret_data.entries))
                # Serialize and store
                secrets_pt = pol.serialization.son_to_string(secret_data)
                secrets_ct = cipherstream.encrypt(secrets_pt)
                self.main_data = self.main_data._replace(iv=iv,
                                        secrets=secrets_ct)
            # Write main slice
            if self.main_data:
                assert self.list_key and self.main_slice
                # Filter entries that are marked for deletion
                main_data = self.main_data._replace(
                        entries=filter(lambda x: x is not None,
                                        self.main_data.entries))
                # Serialize and store
                main_pt = pol.serialization.son_to_string(main_data)
                self.main_slice.store(self.list_key, main_pt, annex=annex)
            # Write append slice
            if self.append_data:
                assert self.append_key and self.append_slice
                # First apply pending updates
                for index, entry in self.append_data_updates.iteritems():
                    if entry is None:
                        self.append_data.entries[index] = None
                    else:
                        self.append_data.entries[index] = self.safe.envelope.seal(
                                    pol.serialization.son_to_string(entry),
                                    self.append_data.pubkey)
                # Then, filter entries marked for deletion
                append_data = self.append_data._replace(
                        entries=filter(lambda x: x is not None,
                                        self.append_data.entries))
                # Serialize and store
                append_pt = pol.serialization.son_to_string(append_data)
                self.append_slice.store(self.append_key, append_pt, annex=annex)
            self.unsaved_changes = False

        def list(self):
            if not self.main_data:
                raise MissingKey
            ret = []
            for i, entry in enumerate(self.main_data.entries):
                if entry is None:
                    continue
                ret.append(ElGamalSafe.MainEntry(self, i))
            if self.secret_data and self.append_data:
                for i, raw_entry in enumerate(self.append_data.entries):
                    ret.append(ElGamalSafe.AppendEntry(self, i,
                                *self.safe.envelope.open(raw_entry,
                                        self.secret_data.privkey)))
            return ret

        def get(self, key):
            if not self.main_data:
                raise MissingKey
            for i, entry in enumerate(self.main_data.entries):
                if entry is None:
                    continue
                if entry[0] != key:
                    continue
                yield ElGamalSafe.MainEntry(self, i)
            if self.secret_data and self.append_data:
                for i, raw_entry in enumerate(self.append_data.entries):
                    if raw_entry is None:
                        continue
                    entry = pol.serialization.string_to_son(
                                self.safe.envelope.open(raw_entry,
                                            self.secret_data.privkey))
                    if entry[0] != key:
                        continue
                    yield ElGamalSafe.AppendEntry(self, i, *entry)

        def add(self, key, note, secret):
            if self.secret_data:
                self.main_data.entries.append((key, note))
                self.secret_data.entries.append(secret)
            elif self.append_data:
                self.append_data.entries.append(None)
                self.append_data_updates[
                        len(self.append_data.entries)-1] = [key, note, secret]
            else:
                raise MissingKey
            self.unsaved_changes = True

        @property
        def can_add(self):
            return bool(self.secret_data) or bool(self.append_data)
        @property
        def has_secrets(self):
            return bool(self.secret_data)
        @property
        def id(self):
            return (self.append_slice.first_index if self.append_slice else
                            self.main_slice.first_index)

        def touch(self):
            self.unsaved_changes = True

    class Slice(object):
        def __init__(self, safe, indices, value=None):
            self.safe = safe
            self.indices = indices
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
        def first_index(self):
            return self.indices[0]
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
            time_started = time.time()
            l.debug('Slice.store: storing @%s; %s blocks; %s/%sB',
                    self.indices[0], len(self.indices), len(value),
                    total_size)
            # Secondly, generate an IV and get a cipherstream
            iv = randfunc(self.safe.cipher.blocksize)
            cipher = self.safe._cipherstream(key, iv)
            # Thirdly, prepare the ciphertext
            plaintext = (self.safe._index_to_bytes(len(self.indices))
                          + ''.join([self.safe._index_to_bytes(index)
                                      for index in self.indices[1:]])
                          + self.safe._slice_size_to_bytes(len(value))
                          + value).ljust(bpb * len(self.indices), '\0')
            ciphertext = (self.safe.kd([self.safe._cipherstream_key(key)],
                                        length=self.safe.cipher.blocksize)
                                + iv
                                + cipher.encrypt(plaintext))
            # Finally, write the blocks
            for index, raw_block in pol.parallel.parallel_map(
                    self._store_block,
                    [(ciphertext[bpb*indexindex:bpb*(indexindex+1)], index)
                        for indexindex, index in enumerate(self.indices)],
                    args=(key, annex),
                    initializer=self._store_block_initializer,
                    nworkers=self.safe.nworkers,
                    use_threads=self.safe.use_threads,
                    chunk_size=8):
                if raw_block is None:
                    raise WrongKeyError
                self.safe._write_block(index, raw_block)
            self._value = value
            duration = time.time() - time_started
            l.debug('Slice.store:  ... done in %.3f (%.1f block/s)',
                        duration, len(self.indices) / duration)
            self.safe.touch()

        def _store_block(self, ct_index, key, annex, randfunc):
            try:
                ct, index = ct_index
                return index, self.safe._eg_encrypt_block(key, index, ct,
                                                randfunc, annex=annex)
            except WrongKeyError:
                # TODO it would  be prettier if parallel_map passes the
                #      exception
                return index, None
        def _store_block_initializer(self, args, kwargs):
            Crypto.Random.atfork()
            kwargs['randfunc'] = Crypto.Random.new().read

    def __init__(self, data, nworkers, use_threads):
        super(ElGamalSafe, self).__init__(data, nworkers, use_threads)
        # Check if `data' makes sense.
        self.free_blocks = set([])
        self.auto_save_containers = []
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
                    ks=None, kd=None, envelope=None, blockcipher=None,
                    gp_bits=1025, precomputed_gp=False, nworkers=None,
                    use_threads=False, progress=None):
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
        if envelope is None:
            envelope = pol.envelope.Envelope.setup()
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
                 'group-params': [pol.serialization.number_to_string(x)
                                         for x in gp],
                 'key-stretching': ks.params,
                 'key-derivation': kd.params,
                 'envelope': envelope.params,
                 'block-cipher': cipher.params,
                 'blocks': [['','','',''] for i in xrange(n_blocks)]},
                        nworkers, use_threads)
        # Mark all blocks as free
        safe.mark_free(xrange(n_blocks))
        return safe

    def open_containers(self, password, additional_keys=None, autosave=True,
                            move_append_entries=True,
                            on_move_append_entries=None):
        """ Opens a container.

            If there are entries in the append-slice, `on_move_append_entries'
            will be called with the entries as only argument. """
        l.debug('open_containers: Stretching key')
        access_key = self.ks(self._composite_password(
                                    password, additional_keys))
        l.debug('open_containers: Searching for access slice ...')
        for sl in self._find_slices(access_key):
            access_data = access_tuple(*pol.serialization.string_to_son(
                                sl.value))
            if access_data.magic != AS_MAGIC:
                l.warn('Wrong magic on access slice')
                continue
            l.debug('open_containers:  found one @%s; type %s',
                            sl.first_index, access_data.type)
            container = self._open_container_with_access_data(
                            access_data, move_append_entries,
                            on_move_append_entries)
            if autosave:
                self.auto_save_containers.append(container)
            yield container

    def _open_container_with_access_data(self, access_data,
                        move_append_entries=True,
                        on_move_append_entries=None):
        (full_key, list_key, append_key, main_slice, append_slice, main_data,
                append_data, secret_data, append_index, main_index) = (None,
                        None, None, None, None, None, None, None, None, None)
        # First, derive keys from the current key
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
            main_data = main_tuple(*pol.serialization.string_to_son(
                                    main_slice.value))
            append_key = self.kd([list_key, KD_APPEND])
            append_index = main_data.append_index
        # Now, read secret data if we have access
        if full_key:
            cipherstream = self._cipherstream(full_key, main_data.iv)
            secret_data = secret_tuple(*pol.serialization.string_to_son(
                            cipherstream.decrypt(main_data.secrets)))
        # Read the append-data, if it exists
        moved_entries = False
        if append_index is not None:
            append_slice = self._load_slice(append_key, append_index)
            append_data = append_tuple(*pol.serialization.string_to_son(
                                    append_slice.value))
            # Move entries from append-data to the secret data
            if append_data.entries and secret_data and move_append_entries:
                new_entries = []
                for raw_entry in append_data.entries:
                    new_entries.append(pol.serialization.string_to_son(
                                 self.envelope.open(raw_entry,
                                                    secret_data.privkey)))
                if new_entries:
                    moved_entries = True
                    if on_move_append_entries:
                        on_move_append_entries(new_entries)
                append_data = append_data._replace(entries=[])
                for entry in new_entries:
                    secret_data.entries.append(entry[2])
                    main_data.entries.append(entry[:2])
        container = ElGamalSafe.Container(self, full_key, list_key, append_key,
                    main_slice, append_slice, main_data, append_data,
                    secret_data)
        if moved_entries:
            container.touch()
        return container

    def new_container(self, password, list_password=None, append_password=None,
                            additional_keys=None, nblocks=170, randfunc=None):
        """ Create a new container. """
        # TODO support access blocks of more than one block in size.
        # TODO check append_slice_size makes sense
        append_slice_size = 5
        append_slice, append_data = None, None
        pubkey, privkey = None, None
        if randfunc is None:
            randfunc = Crypto.Random.new().read
        if len(self.free_blocks) < nblocks:
            raise SafeFullError
        # Divide blocks
        nblocks_mainslice = nblocks - 1
        if list_password:
            nblocks_mainslice -= 1
        if append_password or list_password:
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
        # Generate envelope keypair
        if append_slice:
            l.debug('new container: generating envelope keypair')
            pubkey, privkey = self.envelope.generate_keypair()
        # Generate the keys of the container
        l.debug('new_container: deriving keys')
        full_key = randfunc(self.kd.size)
        list_key = self.kd([full_key, KD_LIST])
        append_key = self.kd([list_key, KD_APPEND])
        # Derive keys from passwords
        as_full_key = self.ks(self._composite_password(
                                password, additional_keys))
        if append_password:
            as_append_key = self.ks(self._composite_password(
                                append_password, additional_keys))
        if list_password:
            as_list_key = self.ks(self._composite_password(
                                list_password, additional_keys))
        # Create access slices
        l.debug('new_container: creating access slices')
        as_full.store(as_full_key, pol.serialization.son_to_string(
                    access_tuple(magic=AS_MAGIC,
                                 type=AS_FULL,
                                 index=main_slice.first_index,
                                 key=full_key)), annex=True)
        if append_password:
            as_append.store(as_append_key, pol.serialization.son_to_string(
                    access_tuple(magic=AS_MAGIC,
                                 type=AS_APPEND,
                                 index=append_slice.first_index,
                                 key=append_key)), annex=True)
        if list_password:
            as_list.store(as_list_key, pol.serialization.son_to_string(
                    access_tuple(magic=AS_MAGIC,
                                 type=AS_LIST,
                                 index=main_slice.first_index,
                                 key=list_key)), annex=True)
        # Initialize main and append slices
        if append_slice:
            append_data = append_tuple(magic=APPEND_SLICE_MAGIC,
                                 pubkey=pubkey,
                                 entries=[])
        main_data = main_tuple(magic=MAIN_SLICE_MAGIC,
                               append_index=(append_slice.first_index
                                                if append_slice else None),
                               entries=[],
                               iv=None,
                               secrets=None)
        secret_data = secret_tuple(privkey=privkey,
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
                    *[pol.serialization.string_to_number(x)
                        for x in self.data['group-params']])

    def mark_free(self, indices):
        """ Marks the given indices as free. """
        self.free_blocks.update(indices)

    def trash_freespace(self):
        if not self.free_blocks:
            return
        l.debug('trash_freespace: trashing')
        sl = self._new_slice(len(self.free_blocks))
        sl.trash()

    def autosave_containers(self):
        for container in self.auto_save_containers:
            if not container:
                continue
            if container.unsaved_changes:
                container.save()

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
        pol.xrandom.shuffle(free_blocks)
        indices = free_blocks[:nblocks]
        self.free_blocks = set(free_blocks[nblocks:])
        ret = ElGamalSafe.Slice(self, indices)
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
        time_started = time.time()
        indices = [index]
        offset = self.cipher.blocksize
        iv = fbct[offset:offset+self.cipher.blocksize]
        offset += self.cipher.blocksize
        cipherstream = self._cipherstream(key, iv)
        # Secondly, read the amount of blocks in the slice
        pt = cipherstream.decrypt(fbct[offset:])
        indices_to_read = self._index_from_bytes(
                            pt[:self.block_index_size]) - 1
        offset = self.block_index_size
        # Now, read the indices
        indexindex = 0
        while indices_to_read:
            if offset + self.block_index_size > len(pt):
                indexindex += 1
                assert len(indices) > indexindex
                pt += cipherstream.decrypt(self._eg_decrypt_block(
                                            key, indices[indexindex]))
            indices.append(self._index_from_bytes(
                            pt[offset:offset+self.block_index_size]))
            offset += self.block_index_size
            indices_to_read -= 1
        # Read the remaining blocks
        pt += ''.join(pol.parallel.parallel_map(
                self._load_block,
                [(ii*self.bytes_per_block - self.cipher.blocksize*2,
                                indices[ii])
                        for ii in xrange(indexindex+1, len(indices))],
                args=(self._cipherstream_key(key), key, iv),
                initializer=self._load_block_initializer,
                nworkers=self.nworkers,
                use_threads=self.use_threads,
                chunk_size=8))
        # Read size
        size = self._slice_size_from_bytes(pt[offset:offset+self.slice_size])
        offset += self.slice_size
        ret = ElGamalSafe.Slice(self, indices, pt[offset:offset+size])
        duration = time.time() - time_started
        l.debug('_load_slice_from_first_block:   %s blocks;'+
                    ' %.3fs (%.1f blocks/s)',
                    len(indices), duration, len(indices) / duration)
        return ret

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
        # TODO is it safe to reduce the size of privkey by this much?
        return pol.serialization.string_to_number(
                    self.kd([key, KD_ELGAMAL, self._index_to_bytes(index)],
                            length=self.bytes_per_block))

    # ElGamal encryption and decryption
    def _load_block_initializer(self, args, kwargs):
        Crypto.Random.atfork()
    def _load_block(self, offset_index, cipherstream_key, key, iv):
        offset, index = offset_index
        return self.cipher.new_stream(cipherstream_key, iv,
                offset=offset).decrypt(self._eg_decrypt_block(key, index))

    def _eg_decrypt_block(self, key, index):
        """ Decrypts the block `index' with `key' """
        marker = self._marker_for_block(key, index)
        if self.data['blocks'][index][3] != marker:
            raise WrongKeyError
        privkey = self._privkey_for_block(key, index)
        gp = self.group_params
        c1 = pol.serialization.string_to_number(self.data['blocks'][index][0])
        c2 = pol.serialization.string_to_number(self.data['blocks'][index][1])
        return pol.elgamal.decrypt(c1, c2, privkey, gp, self.bytes_per_block)
    def _write_block(self, index, block):
        """ Apply changes returned by `_eg_encrypt_block'. """
        self.data['blocks'][index][0] = block[0]
        self.data['blocks'][index][1] = block[1]
        if block[2] is not None:
            self.data['blocks'][index][2] = block[2]
        if block[3] is not None:
            self.data['blocks'][index][3] = block[3]
    def _eg_encrypt_block(self, key, index, s, randfunc, annex=False):
        """ Returns the changed entries for block `index' such that it
            encrypts `s' using `key'.  Use `_write_block' to apply. """
        # We do not write immediately, such that _eg_encrypt_block can
        # be called in a separate process.
        assert len(s) <= self.bytes_per_block
        ret = [None, None, None, None]
        privkey = self._privkey_for_block(key, index)
        gp = self.group_params
        marker = self._marker_for_block(key, index)
        if self.data['blocks'][index][3] != marker:
            if not annex:
                raise WrongKeyError
            pubkey = pol.elgamal.pubkey_from_privkey(privkey, gp)
            binary_pubkey = pol.serialization.number_to_string(pubkey)
            ret[2] = binary_pubkey
            ret[3] = marker
        else:
            pubkey = pol.serialization.string_to_number(
                        self.data['blocks'][index][2])
        # TODO is it safe to pick r so much smaller than p?
        c1, c2 = pol.elgamal.encrypt(s, pubkey, gp,
                                     self.bytes_per_block, randfunc)
        ret[0] = pol.serialization.number_to_string(c1)
        ret[1] = pol.serialization.number_to_string(c2)
        return ret
    def _composite_password(self, password, additional_keys):
        additional_keys = list(sorted(additional_keys
                                        if additional_keys else []))
        return (self.kd([password] + additional_keys)
                            if additional_keys else password)

def _eg_rerandomize_block_initializer(args, kwargs):
    Crypto.Random.atfork()
def _eg_rerandomize_block(raw_b, g, p):
    """ Rerandomizes raw_b given group parameters g and p. """
    s = random.randint(2, int(p))
    b = [pol.serialization.string_to_number(raw_b[0]),
         pol.serialization.string_to_number(raw_b[1]),
         pol.serialization.string_to_number(raw_b[2])]
    b[0] = (b[0] * pow(g, s, p)) % p
    b[1] = (b[1] * pow(b[2], s, p)) % p
    raw_b[0] = pol.serialization.number_to_string(b[0])
    raw_b[1] = pol.serialization.number_to_string(b[1])
    return raw_b

TYPE_MAP = {'elgamal': ElGamalSafe}
