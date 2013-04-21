""" Extensions to PyCrypto's random functions """

import math

import Crypto.Random.random

def shuffle(s):
    """ The same as Crypto.Random.random.shuffle, but faster. """
    r = Crypto.Random.random.randrange(0, math.factorial(len(s)))
    for i in xrange(len(s)-1, 0, -1):
        r, j = divmod(r, i+1)
        s[i], s[j] = s[j], s[i]
