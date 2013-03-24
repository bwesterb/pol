""" Implementation of key derivation  """

import logging

import scrypt

l = logging.getLogger(__name__)

class KeyDerivationParameterError(ValueError):
    pass

class KeyDerivation(object):
    """ Derives a key from a password. """

    def __init__(self, params):
        """ Initialize the KeyDerivation with the given parameters.

            NOTE use KeyDerivation.setup """
        self.params = params

    @staticmethod
    def setup(params=None):
        """ Set-up the key-derivation given by `params`. """
        if params is None:
            params = {'type': 'scrypt',
                      'Nexp': 15,
                      'r': 8,
                      'p': 1}
        if ('type' not in params or not isinstance(params['type'], basestring)
                or params['type'] not in TYPE_MAP):
            raise KeyDerivationParameterError("Invalid `type' attribute")
        return TYPE_MAP[params['type']](params)

    def derive(self, password, salt):
        raise NotImplementedError

class ScryptKeyDerivation(KeyDerivation):
    """ scrypt is the default key derivation """

    def __init__(self, params):
        super(ScryptKeyDerivation, self).__init__(params)
        for attr in ('Nexp', 'r', 'p'):
            if not attr in params:
                raise KeyDerivationParameterError("Missing param `%s'" % attr)
            if not isinstance(params[attr], int):
                raise KeyDerivationParameterError("%s should be int" % attr)
            if params[attr] < 0:
                raise KeyDerivationParameterError("%s should be positive"% attr)
        if params['r'] * params['p'] >= 2**30:
            raise KeyDerivationParameterError("r*p is too large")
        if params['Nexp'] <= 1:
            raise KeyDerivationParameterError("Nexp is too small")

    def derive(self, password, salt):
        return scrypt.hash(password,
                           salt,
                           2**self.params['Nexp'],
                           self.params['r'],
                           self.params['p'])

TYPE_MAP = {'scrypt': ScryptKeyDerivation}
