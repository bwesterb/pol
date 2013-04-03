""" Code to read psafe3 databases """

import hmac
import uuid
import struct
import hashlib
import logging
import datetime
import cStringIO as StringIO

import mcrypt

l = logging.getLogger(__name__)

TAG = 'PWS3'
EOF = 'PWS3-EOFPWS3-EOF'

class BadPasswordError(ValueError):
    pass

class PSafe3FormatError(ValueError):
    pass

class IntegrityError(ValueError):
    pass

def stretch_key(key, salt, niter):
    h = hashlib.sha256()
    h.update(key)
    h.update(salt)
    H = h.digest()
    for i in xrange(niter):
        H = hashlib.sha256(H).digest()
    return H

def load(f, password):
    l.debug('Reading header ...')
    tag = f.read(4)
    if tag != TAG:
        raise PSafe3FormatError("Tag is wrong.  Is this a PSafe3 file?")
    salt = f.read(32)
    niter = struct.unpack("<I", f.read(4))[0]

    l.debug('Stretching password ...')
    P2 = stretch_key(password, salt, niter)
    HP2 = hashlib.sha256(P2).digest()
    if HP2 != f.read(32):
        raise BadPasswordError

    l.debug('Reading header ...')
    m = mcrypt.MCRYPT('twofish', 'ecb')
    m.init(P2)
    K = m.decrypt(f.read(32))
    L = m.decrypt(f.read(32))
    IV = f.read(16)

    m = mcrypt.MCRYPT('twofish', 'cbc')
    m.init(K, IV)

    l.debug('Decrypting ...')
    plaintext = ''
    hmac_data = ''
    while True:
        b = f.read(16)
        if b == EOF:
            break
        plaintext += m.decrypt(b)

    l.debug('Reading decrypted header ...')
    g = StringIO.StringIO(plaintext)
    in_header = True
    header = {}
    record = {}
    records = []
    had = set()
    while True:
        field = g.read(5)
        if not field:
            break
        length, t = struct.unpack("<IB", field)
        d = g.read(length)
        hmac_data += d
        if t in had:
            l.warn("Field type %s occurs twice", t)
        had.add(t)
        if in_header:
            if t == 0:
                header['version']  = struct.unpack("<H", d)[0]
            elif t == 1:
                header['uuid'] = uuid.UUID(bytes=d)
            elif t == 2:
                header['non-default-preferences'] = d
            elif t == 3:
                header['tree-display-status'] = d
            elif t == 4:
                header['last-save'] = datetime.datetime.fromtimestamp(
                                        struct.unpack("<I", d)[0])
            elif t == 5:
                header['last-save-who'] = d
            elif t == 6:
                header['last-save-what'] = d
            elif t == 7:
                header['last-save-by-user'] = d
            elif t == 8:
                header['last-save-on-host'] = d
            elif t == 9:
                header['database-name'] = d
            elif t == 10:
                header['database-description'] = d
            elif t == 11:
                header['database-filters'] = d
            elif t == 15:
                header['recently-used-filters'] = d
            elif t == 16:
                header['named-password-policies'] = d
            elif t == 17:
                header['empty-groups'] = d
            elif t == 255:
                in_header = False
                had = set()
            else:
                l.warn("Unknown header field: type %s; data %s",
                            t, repr(d))
        else:
            if t == 1:
                record['uuid'] = uuid.UUID(bytes=d)
            elif t == 2:
                record['group'] = d
            elif t == 3:
                record['title'] = d
            elif t == 4:
                record['username'] = d
            elif t == 5:
                record['notes'] = d
            elif t == 6:
                record['password'] = d
            elif t == 7:
                record['creation-time'] = datetime.datetime.fromtimestamp(
                                        struct.unpack("<I", d)[0])
            elif t == 8:
                record['password-modification-time'] = (
                        datetime.datetime.fromtimestamp(
                                        struct.unpack("<I", d)[0]))
            elif t == 9:
                record['last-access-time'] = datetime.datetime.fromtimestamp(
                                        struct.unpack("<I", d)[0])
            elif t == 10:
                record['password-expiry-time'] = (
                        datetime.datetime.fromtimestamp(
                                        struct.unpack("<I", d)[0]))
            elif t == 12:
                record['last-modification-time'] = (
                        datetime.datetime.fromtimestamp(
                                        struct.unpack("<I", d)[0]))
            elif t == 13:
                record['url'] = d
            elif t == 14:
                record['autotype'] = d
            elif t == 15:
                record['password-history'] = d
            elif t == 16:
                record['password-policy'] = d
            elif t == 17:
                record['password-expiry-interval'] = d
            elif t == 18:
                record['run-command'] = d
            elif t == 19:
                record['double-click-action'] = d
            elif t == 20:
                record['email-address'] = d
            elif t == 21:
                record['protected-entry'] = (d != chr(0))
            elif t == 22:
                record['own-symbols-for-password'] = d
            elif t == 23:
                record['shift-double-click-action'] = d
            elif t == 24:
                record['password-policy-name'] = d
            elif t == 255:
                records.append(record)
                record = {}
                had = set()
            else:
                l.warn("Unknown record field: type %s; data %s",
                            t, repr(d))
        tl = length + 5
        if tl % 16 != 0:
            g.read(16 - (tl % 16))
    l.debug('Checking HMAC ...')
    if hmac.new(L, hmac_data, hashlib.sha256).digest() != f.read(32):
        raise IntegrityError
    return (header, records)
