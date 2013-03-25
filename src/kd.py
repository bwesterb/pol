""" Implementation of key derivation  """

import logging

import scrypt

# FIXME There is a bug in scrypt 0.5.5 that causes a crash when we
#       try to specify r or p.

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
                      #'r': 8,
                      #'p': 1,
                      'Nexp': 15}
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
        #for attr in ('Nexp', 'r', 'p'):
        for attr in ('Nexp',):
            if not attr in params:
                raise KeyDerivationParameterError("Missing param `%s'" % attr)
            if not isinstance(params[attr], int):
                raise KeyDerivationParameterError("%s should be int" % attr)
            if params[attr] < 0:
                raise KeyDerivationParameterError("%s should be positive"% attr)
        #if params['r'] * params['p'] >= 2**30:
        #    raise KeyDerivationParameterError("r*p is too large")
        if params['Nexp'] <= 1:
            raise KeyDerivationParameterError("Nexp is too small")

    def derive(self, password, salt):
        return scrypt.hash(password,
                           salt,
                           #r=self.params['r'],
                           #p=self.params['p'],
                           N=2**self.params['Nexp'])

TYPE_MAP = {'scrypt': ScryptKeyDerivation}
