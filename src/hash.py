""" Implementation of hashing """

import logging
import hashlib

import Crypto.Random

l = logging.getLogger(__name__)

class HashParameterError(ValueError):
    pass

class Hash(object):
    """ Cryptographically secure one-way reduction """

    def __init__(self, params):
        """ Initialize the Hash with the given parameters.

            NOTE use Hash.setup """
        self.params = params

    @staticmethod
    def setup(params=None, randfunc=None):
        """ Set-up the hash given by `params`.
        
            If `params' is None, generates new parameters.  In that case
            `randfunc' is used to generate a salt. """
        if params is None:
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            params = {'type': 'sha',
                      'bits': 256,
                      'salt': randfunc(32)}
        if ('type' not in params or not isinstance(params['type'], basestring)
                or params['type'] not in TYPE_MAP):
            raise HashParameterError("Invalid `type' attribute")
        return TYPE_MAP[params['type']](params)

    def single(self, data):
        """ Computes the hash of a single string. """
        raise NotImplementedError

    def multiple(self, *args):
        """ Computes the hash of a list of strings. """
        tmp = ''
        for arg in args:
            tmp += self.single(arg)
        return self.single(tmp)

class SHAHash(Hash):
    """ SHA is the default key derivation """

    def __init__(self, params):
        super(SHAHash, self).__init__(params)
        if not 'salt' in params:
            raise HashParameterError("Missing param `salt'")
        if not 'bits' in params:
            raise HashParameterError("Missing param `bits'")
        if not isinstance(params['salt'], basestring):
            raise HashParameterError("`salt' should be a string")
        if not isinstance(params['bits'], int):
            raise HashParameterError("`bits' should be int")
        if params['bits'] not in (256,):
            raise HashParameterError("We do not support the given `bits'")
        self.bits = params['bits']
        self.salt = params['salt']

    def single(self, data):
        """ Computes the hash of a single string. """
        if self.bits == 256:
            h = hashlib.sha256(data)
            h.update(self.salt)
            return h.digest()

TYPE_MAP = {'sha': SHAHash}
