""" Password generation """

import logging

import Crypto.Random

l = logging.getLogger(__name__)

alphabet = ('qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM'+
            '!@#$%^&*(){}[]-=_+,.<>/?')

# TODO stub: make `correct horse battery stable'-style passwords the default
def generate_password():
    ret = ''
    for i in xrange(10):
        ret += Crypto.Random.random.choice(alphabet)
    return ret
