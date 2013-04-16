import gmpy
import msgpack

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
    return msgpack.dumps(obj)

def string_to_son(s):
    return msgpack.loads(s, use_list=True)
