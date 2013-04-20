""" Read KeePass 1.x databases """

import uuid
import struct
import logging
import hashlib
import binascii
import datetime
import cStringIO as StringIO

# py-crypto
import Crypto.Cipher.AES

class BadPasswordError(ValueError):
    pass

class KeePassFormatError(ValueError):
    pass

SIGNATURE = binascii.unhexlify('03d9a29a65fb4bb5')

FLAG_SHA2       = 1
FLAG_RIJNDAEL   = 2
FLAG_ARC4       = 4
FLAG_TWOFISH    = 8

l = logging.getLogger(__name__)

def unpack_datetime(s):
    # 76543210 76543210 76543210 76543210 76543210
    # yyyyyyyy yyyyyymm mmdddddh hhhhmmmm mmssssss
    if len(s) != 5:
        raise KeePassFormatError("Date/time data must be 5 bytes")
    b = map(ord, s)
    year  =  (b[0]               << 6) | (b[1] >> 2)
    month = ((b[1] & 0b00000011) << 2) | (b[2] >> 6)
    day   =  (b[2] & 0b00111111) >> 1
    hour  =  (b[2] & 0b00000001) << 4  | (b[3] >> 4)
    mins  = ((b[3] & 0b00001111) << 2) | (b[4] >> 6)
    secs  =  (b[4] & 0b00111111)
    return datetime.datetime(year, month, day, hour, mins, secs)

def masterkey_to_finalkey(masterkey, master_seed, master_seed2, key_enc_rounds):
    key = hashlib.sha256(masterkey).digest()
    cipher = Crypto.Cipher.AES.new(master_seed2, Crypto.Cipher.AES.MODE_ECB)
    for r in xrange(key_enc_rounds):
        key = cipher.encrypt(key)
    key = hashlib.sha256(key).digest()
    return hashlib.sha256(master_seed + key).digest()

def load(f, password, keyfile=None):
    if keyfile:
        l.debug('Reading keyfile ...')
        keyfile_bit = keyfile.read()
        if len(keyfile_bit) == 32:
            pass
        elif len(keyfile_bit) == 64:
            keyfile_bit = binascii.unhexlify(keyfile_bit)
        else:
            keyfile_bit = hashlib.sha256(keyfile_bit).digest()
    else:
        keyfile_bit = None

    l.debug('Reading header ...')
    signature = f.read(8)
    if signature != SIGNATURE:
        raise KeePassFormatError('Invalid signature.  Is this a KeePass file?')
    flags, version = struct.unpack('<II', f.read(8))
    master_seed = f.read(16)
    encryption_iv = f.read(16)
    ngroups, nentries  = struct.unpack('<II', f.read(8))
    contents_hash = f.read(32)
    master_seed2 = f.read(32)
    key_enc_rounds = struct.unpack('<I', f.read(4))[0]

    if flags != FLAG_SHA2 | FLAG_RIJNDAEL:
        raise NotImplementedError

    l.debug('Deriving finalkey ...')
    if keyfile_bit:
        compositekey = hashlib.sha256(password).digest() + keyfile_bit
    else:
        compositekey = password
    finalkey = masterkey_to_finalkey(compositekey, master_seed, master_seed2,
                        key_enc_rounds)

    l.debug('Reading remaining ciphertext ...')
    ciphertext = f.read()

    l.debug('Decrypting ...')
    cipher = Crypto.Cipher.AES.new(finalkey, Crypto.Cipher.AES.MODE_CBC,
                                            encryption_iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = padded_plaintext[:-ord(padded_plaintext[-1])]

    l.debug('Verifying hash ...')
    if hashlib.sha256(plaintext).digest() != contents_hash:
        raise BadPasswordError

    l.debug('Parsing groups ...')
    groups_found = 0
    g = StringIO.StringIO(plaintext)
    groups = {}
    current_group = {}
    had = set()
    while groups_found < ngroups:
        field_type, field_size = struct.unpack('<HI', g.read(6))
        if field_type in had:
            raise KeePassFormatError("Same field type occurs twice")
        had.add(field_type)
        data = g.read(field_size)
        if field_type == 0:
            l.debug(' comment %s', field_type, repr(data))
        elif field_type == 1:
            if len(data) != 4:
                raise KeePassFormatError("Group ID data must be 4 bytes")
            value = struct.unpack('<I', data)[0]
            current_group['id'] = value
            l.debug(' id %s', value)
        elif field_type == 2:
            value = data[:-1].decode('utf-8')
            current_group['name'] = value
            l.debug(' name %s', value)
        elif field_type == 3:
            value = unpack_datetime(data)
            current_group['creation-time'] = value
            l.debug(' creation-time %s', value)
        elif field_type == 4:
            value = unpack_datetime(data)
            current_group['last-modification-time'] = value
            l.debug(' last-modification-time %s', value)
        elif field_type == 5:
            value = unpack_datetime(data)
            current_group['last-access-time'] = value
            l.debug(' last-access-time %s', value)
        elif field_type == 6:
            value = unpack_datetime(data)
            current_group['expiration-time'] = value
            l.debug(' expiration-time %s', value)
        elif field_type == 7:
            if len(data) != 4:
                raise KeePassFormatError("Image ID data must be 4 bytes")
            value = struct.unpack('<I', data)[0]
            current_group['image-id'] = value
            l.debug(' image-id %s', value)
        elif field_type == 8:
            if len(data) != 2:
                raise KeePassFormatError("Level data must be 2 bytes")
            value = struct.unpack('<H', data)[0]
            current_group['level'] = value
            l.debug(' level %s', value)
        elif field_type == 9:
            if len(data) != 4:
                raise KeePassFormatError("Flags data must be 2 bytes")
            value = struct.unpack('<I', data)[0]
            current_group['flags'] = value
            l.debug(' flags %s', bin(value))
        elif field_type == 0xffff:
            l.debug(' end-of-group')
            groups_found += 1
            groups[current_group['id']] = current_group
            had = set()
            current_group = {}
        else:
            l.warn(' unknown field %s %s', field_type, repr(data))

    l.debug('Parsing entries ...')
    entries_found = 0
    entries = []
    current_entry = {}
    had = set()
    while entries_found < nentries:
        field_type, field_size = struct.unpack('<HI', g.read(6))
        if field_type in had:
            raise KeePassFormatError("Same field type occurs twice")
        had.add(field_type)
        data = g.read(field_size)
        if field_type == 0:
            l.debug(' comment %s', field_type, repr(data))
        elif field_type == 1:
            if len(data) != 16:
                raise KeePassFormatError("UUID data must be 16 bytes")
            value = uuid.UUID(bytes=data)
            current_entry['uuid'] = value
            l.debug(' uuid %s', value)
        elif field_type == 2:
            if len(data) != 4:
                raise KeePassFormatError("Group ID data must be 16 bytes")
            value = struct.unpack("<I", data)[0]
            current_entry['group'] = value
            l.debug(' group %s', value)
        elif field_type == 3:
            if len(data) != 4:
                raise KeePassFormatError("Image ID data must be 16 bytes")
            value = struct.unpack("<I", data)[0]
            current_entry['image-id'] = value
            l.debug(' image-id %s', value)
        elif field_type == 4:
            value = data[:-1].decode('utf-8')
            current_entry['title'] = value
            l.debug(' title %s', value)
        elif field_type == 5:
            value = data[:-1].decode('utf-8')
            current_entry['url'] = value
            l.debug(' url %s', value)
        elif field_type == 6:
            value = data[:-1].decode('utf-8')
            current_entry['username'] = value
            l.debug(' username %s', value)
        elif field_type == 7:
            value = data[:-1].decode('utf-8')
            current_entry['password'] = value
            l.debug(' password %s', value)
        elif field_type == 8:
            value = data[:-1].decode('utf-8')
            current_entry['notes'] = value
            l.debug(' notes %s', value)
        elif field_type == 9:
            value = unpack_datetime(data)
            current_entry['creation-time'] = value
            l.debug(' creation-time %s', value)
        elif field_type == 10:
            value = unpack_datetime(data)
            current_entry['last-modification-time'] = value
            l.debug(' last-modification-time %s', value)
        elif field_type == 11:
            value = unpack_datetime(data)
            current_entry['last-access-time'] = value
            l.debug(' last-access-time %s', value)
        elif field_type == 12:
            value = unpack_datetime(data)
            current_entry['expiration-time'] = value
            l.debug(' expiration-time %s', value)
        elif field_type == 13:
            value = data[:-1].decode('utf-8')
            current_entry['binary-description'] = value
            l.debug(' binary-description %s', value)
        elif field_type == 14:
            value = data
            current_entry['binary-data'] = value
            l.debug(' binary-data %s', repr(value))
        elif field_type == 0xffff:
            l.debug(' end-of-entry')
            entries_found += 1
            entries.append(current_entry)
            had = set()
            current_entry = {}
        else:
            l.warn(' unknown field %s %s', field_type, repr(data))
    return (groups, entries)
