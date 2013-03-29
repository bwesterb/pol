""" Implementation of the block ciphers  """

import logging

import Crypto.Cipher.AES

l = logging.getLogger(__name__)

class BlockCipherParameterError(ValueError):
    pass

class BaseStream(object):
    def encrypt(self, s):
        raise NotImplementedError
    def decrypt(self, s):
        raise NotImplementedError

class BlockCipher(object):
    """ Encrypts blocks with a fixed key.  """

    def __init__(self, params):
        """ Initialize the BlockCipher with the given parameters.

            NOTE use BlockCipher.setup """
        self.params = params

    @staticmethod
    def setup(params=None):
        """ Set-up the blockcipher given by `params`. """
        if params is None:
            params = {'type': 'aes',
                      'bits': 256 }
        if ('type' not in params or not isinstance(params['type'], basestring)
                or params['type'] not in TYPE_MAP):
            raise BlockCipherParameterError("Invalid `type' attribute")
        return TYPE_MAP[params['type']](params)

    def new_stream(self, iv):
        raise NotImplementedError

class _AESStream(BaseStream):
    def __init__(self, cipher):
        self.cipher = cipher
    def encrypt(self, s):
        return self.cipher.encrypt(s)
    def decrypt(self, s):
        return self.cipher.decrypt(s)

class AESBlockCipher(BlockCipher):
    """ AES is the default blockcipher """

    def __init__(self, params):
        super(AESBlockCipher, self).__init__(params)
        if not 'bits' in params or params['bits'] not in (256, ):
            raise KeyStretchingParameterError("Invalid param `bits'")
        self.bits = params['bits']

    def new_stream(self, key, iv):
        if len(key) * 8 != self.bits:
            raise ValueError("`key' should be %s long" % (self.bits/8))
        if len(iv) != 16:
            raise ValueError("`iv' should be 16 bytes long")
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
        return _AESStream(cipher)


TYPE_MAP = {'aes': AESBlockCipher}
