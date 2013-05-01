""" Password generation """

import logging
import math

import Crypto.Random.random

import pkg_resources

l = logging.getLogger(__name__)

ALPHABET = {'dense':
                'qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZ'+
                'XCVBNM!@#$%^&*(){}[]-=_+,.<>/?',
            'alphanum':
                'qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZ'+
                'XCVBNM'}
kinds = tuple(ALPHABET.keys()) + ('english', 'dutch')

def generate_password(length=None, entropy=None, kind='dense'):
    add_spaces = False
    if kind == 'english':
        from pol.passgen.english import words as alphabet
        add_spaces = True
    elif kind == 'dutch':
        from pol.passgen.dutch import words as alphabet
        add_spaces = True
    else:
        if kind not in ALPHABET:
            raise ValueError("That `kind' of password is not supported.")
        alphabet = ALPHABET[kind]
    if length and entropy:
        raise ValueError("Only one of `length' and `entropy' "+
                            "should be specified")
    bits = []
    if not (length or entropy):
        entropy = 128
    if not length:
        length = int(math.ceil(entropy / math.log(len(alphabet), 2)))
    for i in xrange(length):
        bits.append(Crypto.Random.random.choice(alphabet))
    if add_spaces:
        return ' '.join(bits)
    return ''.join(bits)
