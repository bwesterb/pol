""" Password generation """

import logging
import math

import Crypto.Random.random

l = logging.getLogger(__name__)

alphabet = ('qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM'+
            '!@#$%^&*(){}[]-=_+,.<>/?')

# TODO add more options
def generate_password(length=None, entropy=None):
    ret = ''
    if length and entropy:
        raise ValueError("Only one of `length' and `entropy' "+
                            "should be specified")
    if not (length or entropy):
        entropy = 128
    if not length:
        length = int(math.ceil(entropy / math.log(len(alphabet), 2)))
    for i in xrange(length):
        ret += Crypto.Random.random.choice(alphabet)
    return ret
