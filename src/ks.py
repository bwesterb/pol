""" Implementation of key stretching  """

import logging

import Crypto.Random
import scrypt

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
            params = {'type': 'scrypt',
                      'salt': randfunc(32),
                      #'r': 8,
                      #'p': 1,
                      'Nexp': 15}
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

TYPE_MAP = {'scrypt': ScryptKeyStretching}
