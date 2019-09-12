import logging

import gmpy2
import zlib
import msgpack

l = logging.getLogger(__name__)

FMT_MSGPACK         = b'\0'
FMT_ZLIB_MSGPACK    = b'\1'

# TODO is the format of gmpy2.{to,from}_binary() stable?
def string_to_number(s):
    """ Converts a string into a number. """
    # gmpy2 binary format for positive numbers:
    #
    # 01 01 [ little endan ]
    # ^  ^
    # |  \- positive
    # \-    mpz
    return gmpy2.from_binary(b'\1\1' + s)

def number_to_string(number):
    """ Converts a number into a string.
    
    Assumes `number' is a positive `gmpy2.mpz'. """
    return gmpy2.to_binary(number)[2:]

def son_to_string(obj):
    t = msgpack.packb(obj, use_bin_type=True)
    tc = zlib.compress(t, 9)
    l.debug(f"son_to_string: original {len(t)}; gzipped: {len(tc)}")
    if len(tc) < len(t):
        return FMT_ZLIB_MSGPACK + tc
    return FMT_MSGPACK + t

def string_to_son(s):
    assert isinstance(s, bytes) # XXX
    if s[0:1] == FMT_ZLIB_MSGPACK:
        tmp = zlib.decompress(s[1:])
    else:
        assert s[0:1] == FMT_MSGPACK
        tmp = s[1:]
    return msgpack.unpackb(tmp, use_list=True, raw=True)

def decode_bytes_in_son(s):
    """ Converts utf8 encoded bytes() to str()s inside the given SON """
    if s is None:
        return None
    if isinstance(s, (str, int, float)):
        return s
    if isinstance(s, bytes):
        return s.decode('utf-8')
    if isinstance(s, list):
        return [decode_bytes_in_son(x) for x in s]
    if isinstance(s, tuple):
        return tuple(decode_bytes_in_son(x) for x in s)
    if isinstance(s, dict):
        return {decode_bytes_in_son(k): decode_bytes_in_son(v)
                    for k,v in s.items()}
    raise NotImplementedError
