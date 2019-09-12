import unittest
import binascii

import pol.envelope

class TestSeccure(unittest.TestCase):
    def setUp(self):
        self.env = pol.envelope.Envelope.setup()
    def test_default(self):
        self.assertEqual(self.env.params[b'type'], b'seccure')
        self.assertEqual(self.env.params[b'curve'], b'secp160r1')
    def test_generate_keypair(self):
        self.env.generate_keypair()
    def test_open(self):
        self.assertEqual(self.env.open(binascii.unhexlify(
            b'00143617e9c11a7f6b58eca06e2c68b4d098ea4f5bf8fa85aab33721f06a0'+
            b'ed4d08bfe7d8ad22bf2ce7507904b3245121df1d88fc691093c77991b3998'),
            b'my private key'),
            b'This is a very secret message\n')
    def test_roundtrip(self):
        msg = b'these are sekrits'
        pubk, privk = self.env.generate_keypair()
        self.assertEqual(self.env.open(self.env.seal(msg, pubk), privk), msg)

if __name__ == '__main__':
    unittest.main()

