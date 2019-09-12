""" Implementation of key stretching  """

import logging

import Crypto.Random

import scrypt

import argon2 # argon2-cffi

# FIXME There is a bug in scrypt 0.5.5 that causes a crash when we
#       try to specify r or p.

l = logging.getLogger(__name__)

class KeyStretchingParameterError(ValueError):
    pass

class KeyStretching(object):
    """ Derives a key from a password. """

    def __init__(self, params):
        """ Initialize the KeyStretching with the given parameters.

            NOTE use KeyStretching.setup """
        self.params = params

    @staticmethod
    def setup(params=None, randfunc=None):
        """ Set-up the key-stretching given by `params`.

            If `params' is None, generates new parameters.  In that case
            `randfunc' is used to generate a salt. """
        if params is None:
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            params = {b'type': b'argon2',
                      b'salt': randfunc(32),
                      b't': 1,
                      b'v': argon2.low_level.ARGON2_VERSION,
                      b'm': 102400,
                      b'p': 4}
        if (b'type' not in params or not isinstance(params[b'type'], bytes)
                or params[b'type'] not in TYPE_MAP):
            raise KeyStretchingParameterError("Invalid `type' attribute")
        return TYPE_MAP[params[b'type']](params)

    def __call__(self, password):
        return self.stretch(password)

    def stretch(self, password):
        raise NotImplementedError


class ScryptKeyStretching(KeyStretching):
    """ scrypt is the default for key stretching """

    def __init__(self, params):
        super(ScryptKeyStretching, self).__init__(params)
        #for attr in ('Nexp', 'r', 'p'):
        for attr in (b'Nexp',):
            if not attr in params:
                raise KeyStretchingParameterError("Missing param `%s'" % attr)
            if not isinstance(params[attr], int):
                raise KeyStretchingParameterError("%s should be int" % attr)
            if params[attr] < 0:
                raise KeyStretchingParameterError("%s should be positive"% attr)
        if not b'salt' in params or not isinstance(params[b'salt'], bytes):
            raise KeyStretchingParameterError("Invalid param `salt'")
        #if params['r'] * params['p'] >= 2**30:
        #    raise KeyStretchingParameterError("r*p is too large")
        if params[b'Nexp'] <= 1:
            raise KeyStretchingParameterError("Nexp is too small")

    def stretch(self, password):
        assert isinstance(password, bytes) # XXX
        return scrypt.hash(password,
                           self.params[b'salt'],
                           #r=self.params['r'],
                           #p=self.params['p'],
                           N=2**self.params[b'Nexp'])

    @staticmethod
    def setup(params=None, randfunc=None):
        if params is None:
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            params = {b'type': b'scrypt',
                      b'salt': randfunc(32),
                      #b'r': 8,
                      #b'p': 1,
                      b'Nexp': 15}
        return KeyStretching.setup(params)

class Argon2KeyStretching(KeyStretching):
    """ argon2 is the winner of the recent Password Hashing Competition.
        It is planned to be the next default for pol.  """

    def __init__(self, params):
        super(Argon2KeyStretching, self).__init__(params)
        if not b'v' in params:
            params[b'v'] = 0x10
        for attr in (b't', b'm', b'p', b'v'):
            if not attr in params:
                raise KeyStretchingParameterError("Missing param `%s'" % attr)
            if not isinstance(params[attr], int):
                raise KeyStretchingParameterError("%s should be int" % attr)
            if params[attr] < 1:
                raise KeyStretchingParameterError("%s cannot be negative"% attr)
        if not b'salt' in params or not isinstance(params[b'salt'], bytes):
            raise KeyStretchingParameterError("Invalid param `salt'")

    def stretch(self, password):
        assert isinstance(password, bytes) # XXX
        return argon2.low_level.hash_secret_raw(
                            secret=password,
                            salt=self.params[b'salt'],
                            time_cost=self.params[b't'],
                            memory_cost=self.params[b'm'],
                            parallelism=self.params[b'p'],
                            hash_len=64,
                            version=self.params[b'v'],
                            type=argon2.low_level.Type.D)

TYPE_MAP = {b'scrypt': ScryptKeyStretching,
            b'argon2': Argon2KeyStretching}
