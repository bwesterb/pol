""" Implementation of envelopes  """

import logging

import seccure

import Crypto.Random

l = logging.getLogger(__name__)

class EnvelopeParameterError(ValueError):
    pass

class Envelope(object):
    """ Seals secrets with public/private cryptography """

    def __init__(self, params):
        """ Initialize the Envelope with the given parameters.

            NOTE use Envelope.setup """
        self.params = params

    @staticmethod
    def setup(params=None):
        """ Set-up the Envelope given by `params`. """
        if params is None:
            params = {'type': 'seccure',
                      'curve': 'secp160r1'}
        if ('type' not in params or not isinstance(params['type'], basestring)
                or params['type'] not in TYPE_MAP):
            raise EnvelopeParameterError("Invalid `type' attribute")
        return TYPE_MAP[params['type']](params)

    def generate_keypair(self):
        """ Generates and returns a (public, private)-keypair """
        raise NotImplementedError
    def seal(self, msg, pubkey):
        """ Seals a message `msg' for public key `pubkey'. """
        raise NotImplementedError
    def open(self, ciphertext, privkey):
        """ Opens ciphertext returned by `seal' with the private
            key `privkey' """
        raise NotImplementedError

class SeccureEnvelope(Envelope):
    """ Implementation of Envelope using a modified version of the
        Integrated Encryption Scheme for Elliptic Curves compatible
        with the commandline utility seccure[1].
        
        [1] http://point-at-infinity.org/seccure/ """
    def __init__(self, params):
        super(SeccureEnvelope, self).__init__(params)
        if not 'curve' in params:
            raise EnvelopeParameterError("Missing param `curve'")
        if not isinstance(params['curve'], basestring):
            raise EnvelopeParameterError("`curve' should be string")
        try:
            self.curve = seccure.Curve.by_name(params['curve'])
        except KeyError:
            raise EnvelopeParameterError("Curve %s not supported"
                                % repr(params['curve']))

    def generate_keypair(self, randfunc=None):
        if randfunc is None:
            randfunc = Crypto.Random.new().read
        privkey = randfunc(self.curve.key_bytes)
        pubkey = self.curve.passphrase_to_pubkey(privkey).to_bytes()
        return (pubkey, privkey)
    def seal(self, msg, pubkey):
        p = self.curve.pubkey_from_string(pubkey)
        return p.encrypt(msg)
    def open(self, ciphertext, privkey):
        p = self.curve.passphrase_to_privkey(privkey)
        return self.curve.decrypt(ciphertext, p)

TYPE_MAP = {'seccure': SeccureEnvelope}
