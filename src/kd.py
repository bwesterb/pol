""" Implementation of key derivation """

import logging
import hashlib
import struct

import Crypto.Random

l = logging.getLogger(__name__)

class KeyDerivationParameterError(ValueError):
    pass

class KeyDerivation(object):
    """ Cryptographically secure one-way key-derivation """

    def __init__(self, params):
        """ Initialize the KeyDerivation with the given parameters.

            NOTE use KeyDerivation.setup """
        self.params = params

    @staticmethod
    def setup(params=None, randfunc=None):
        """ Set-up the keyderivation given by `params`.
        
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
            raise KeyDerivationParameterError("Invalid `type' attribute")
        return TYPE_MAP[params['type']](params)

    def __call__(self, args, length=32):
        return self.derive(args, length)

    def derive(self, args, length=32):
        """ Derives a key of `length' bytes from the list of strings `args'. """
        raise NotImplementedError

    @property
    def size(self):
        """ The "natural" size of the key-derivation """
        raise NotImplementedError

class SHAKeyDerivation(KeyDerivation):
    """ SHA is the default key derivation """

    def __init__(self, params):
        super(SHAKeyDerivation, self).__init__(params)
        if not 'salt' in params:
            raise KeyDerivationParameterError("Missing param `salt'")
        if not 'bits' in params:
            raise KeyDerivationParameterError("Missing param `bits'")
        if not isinstance(params['salt'], basestring):
            raise KeyDerivationParameterError("`salt' should be a string")
        if not isinstance(params['bits'], int):
            raise KeyDerivationParameterError("`bits' should be int")
        if params['bits'] not in (256,):
            raise KeyDerivationParameterError(
                    "We do not support the given `bits'")
        self.bits = params['bits']
        self.salt = params['salt']
        self.word_struct = struct.Struct(">H")

    def _derive(self, args):
        """ Derives `self.bits' bit key from args """
        if self.bits == 256:
            new_hash = hashlib.sha256
        else:
            assert False
        oh = new_hash()
        for arg in args:
            oh.update(new_hash(arg).digest())
        return oh.digest()

    def derive(self, args, length=32):
        ret = ''
        byts = self.bits / 8
        n = length / byts
        if length % byts != 0:
            n += 1
        for i in xrange(n):
            ret += self._derive(args + [self.word_struct.pack(i), self.salt])
        return ret[:length]

    @property
    def size(self):
        return self.bits / 8

TYPE_MAP = {'sha': SHAKeyDerivation}
