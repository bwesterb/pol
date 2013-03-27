""" Implementation of key stretching  """

import logging

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
    def setup(params=None):
        """ Set-up the key-stretching given by `params`. """
        if params is None:
            params = {'type': 'scrypt',
                      #'r': 8,
                      #'p': 1,
                      'Nexp': 15}
        if ('type' not in params or not isinstance(params['type'], basestring)
                or params['type'] not in TYPE_MAP):
            raise KeyStretchingParameterError("Invalid `type' attribute")
        return TYPE_MAP[params['type']](params)

    def derive(self, password, salt):
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
        #if params['r'] * params['p'] >= 2**30:
        #    raise KeyStretchingParameterError("r*p is too large")
        if params['Nexp'] <= 1:
            raise KeyStretchingParameterError("Nexp is too small")

    def derive(self, password, salt):
        return scrypt.hash(password,
                           salt,
                           #r=self.params['r'],
                           #p=self.params['p'],
                           N=2**self.params['Nexp'])

TYPE_MAP = {'scrypt': ScryptKeyStretching}
