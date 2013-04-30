""" Password generation """

import logging
import math

import Crypto.Random.random

l = logging.getLogger(__name__)

ALPHABET = {'dense':
                'qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZ'+
                'XCVBNM!@#$%^&*(){}[]-=_+,.<>/?',
            'alphanum':
                'qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZ'+
                'XCVBNM'}
kinds = ALPHABET.keys()

# TODO xkcd kind
def generate_password(length=None, entropy=None, kind='dense'):
    if kind not in ALPHABET:
        raise ValueError("That `kind' of password is not supported.")
    if length and entropy:
        raise ValueError("Only one of `length' and `entropy' "+
                            "should be specified")
    ret = ''
    alphabet = ALPHABET[kind]
    if not (length or entropy):
        entropy = 128
    if not length:
        length = int(math.ceil(entropy / math.log(len(alphabet), 2)))
    for i in xrange(length):
        ret += Crypto.Random.random.choice(alphabet)
    return ret
