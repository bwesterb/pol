import logging

import gmpy
import zlib
import msgpack

l = logging.getLogger(__name__)

FMT_MSGPACK         = chr(0)
FMT_ZLIB_MSGPACK    = chr(1)

# TODO is the format of gmpy.mpz.binary() stable?
def string_to_number(s):
    """ Converts a string into a number. """
    return gmpy.mpz(s+'\0', 256)

def number_to_string(number):
    """ Converts a number into a string.
    
    Assumes `number' is a `gmpy.mpz'. """
    tmp = number.binary()
    return tmp[:-1] if tmp[-1] == '\0' else tmp

def son_to_string(obj):
    t = msgpack.dumps(obj)
    tc = zlib.compress(t, 9)
    l.debug("son_to_string: original %s; gzipped: %s", len(t), len(tc))
    if len(tc) < len(t):
        return FMT_ZLIB_MSGPACK + tc
    return FMT_MSGPACK + t

def string_to_son(s):
    if s[0] == FMT_ZLIB_MSGPACK:
        tmp = zlib.decompress(s[1:])
    else:
        assert s[0] == FMT_MSGPACK
        tmp = s[1:]
    return msgpack.loads(tmp, use_list=True)
