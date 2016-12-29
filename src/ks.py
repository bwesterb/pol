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
            params = {'type': 'argon2',
                      'salt': randfunc(32),
                      't': 1,
                      'v': argon2.low_level.ARGON2_VERSION,
                      'm': 102400,
                      'p': 4}
        if ('type' not in params or not isinstance(params['type'], basestring)
                or params['type'] not in TYPE_MAP):
            raise KeyStretchingParameterError("Invalid `type' attribute")
        return TYPE_MAP[params['type']](params)

    def __call__(self, password):
        return self.stretch(password)

    def stretch(self, password):
        raise NotImplementedError


class ScryptKeyStretching(KeyStretching):
    """ scrypt is the default for key stretching """

    def __init__(self, params):
        super(ScryptKeyStretching, self).__init__(params)
        #for attr in ('Nexp', 'r', 'p'):
        for attr in ('Nexp',):
            if not attr in params:
                raise KeyStretchingParameterError("Missing param `%s'" % attr)
            if not isinstance(params[attr], int):
                raise KeyStretchingParameterError("%s should be int" % attr)
            if params[attr] < 0:
                raise KeyStretchingParameterError("%s should be positive"% attr)
        if not 'salt' in params or not isinstance(params['salt'], basestring):
            raise KeyStretchingParameterError("Invalid param `salt'")
        #if params['r'] * params['p'] >= 2**30:
        #    raise KeyStretchingParameterError("r*p is too large")
        if params['Nexp'] <= 1:
            raise KeyStretchingParameterError("Nexp is too small")

    def stretch(self, password):
        return scrypt.hash(password,
                           self.params['salt'],
                           #r=self.params['r'],
                           #p=self.params['p'],
                           N=2**self.params['Nexp'])

    @staticmethod
    def setup(params=None, randfunc=None):
        if params is None:
            if randfunc is None:
                randfunc = Crypto.Random.new().read
            params = {'type': 'scrypt',
                      'salt': randfunc(32),
                      #'r': 8,
                      #'p': 1,
                      'Nexp': 15}
        return KeyStretching.setup(params)

class Argon2KeyStretching(KeyStretching):
    """ argon2 is the winner of the recent Password Hashing Competition.
        It is planned to be the next default for pol.  """

    def __init__(self, params):
        super(Argon2KeyStretching, self).__init__(params)
        if not 'v' in params:
            params['v'] = 0x10
        for attr in ('t', 'm', 'p', 'v'):
            if not attr in params:
                raise KeyStretchingParameterError("Missing param `%s'" % attr)
            if not isinstance(params[attr], int):
                raise KeyStretchingParameterError("%s should be int" % attr)
            if params[attr] < 1:
                raise KeyStretchingParameterError("%s cannot be negative"% attr)
        if not 'salt' in params or not isinstance(params['salt'], basestring):
            raise KeyStretchingParameterError("Invalid param `salt'")

    def stretch(self, password):
        return argon2.low_level.hash_secret_raw(
                            secret=password,
                            salt=self.params['salt'],
                            time_cost=self.params['t'],
                            memory_cost=self.params['m'],
                            parallelism=self.params['p'],
                            hash_len=64,
                            version=self.params['v'],
                            type=argon2.low_level.Type.D)

TYPE_MAP = {'scrypt': ScryptKeyStretching,
            'argon2': Argon2KeyStretching}
