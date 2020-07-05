import unittest
import binascii

import pol.blockcipher

class TestAES(unittest.TestCase):
    def setUp(self):
        self.c = pol.blockcipher.BlockCipher.setup()
    def test_default(self):
        self.assertEqual(self.c.params[b'type'], b'aes')
        self.assertEqual(self.c.params[b'bits'], 256)
    def test_encrypt(self):
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!')
        self.assertEqual(binascii.hexlify(s.encrypt(b'1234567890123456')),
                                        b'6cef07fd1ac23d4b6f7429871bb99d8e')
        self.assertEqual(binascii.hexlify(s.encrypt(b'1234567890123456')),
                                        b'2f3f54eba982349b503152c6ec848886')
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!')
        self.assertEqual(binascii.hexlify(s.encrypt(b'1234567890123456'*2)),
                                        b'6cef07fd1ac23d4b6f7429871bb99d8e'+
                                        b'2f3f54eba982349b503152c6ec848886')
    def test_decrypt(self):
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            b'6cef07fd1ac23d4b6f7429871bb99d8e')),
                            b'1234567890123456')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            b'2f3f54eba982349b503152c6ec848886')),
                            b'1234567890123456')
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            b'6cef07fd1ac23d4b6f7429871bb99d8e'+
                            b'2f3f54eba982349b503152c6ec848886')),
                            b'1234567890123456'*2)
    def test_offset(self):
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!')
        p1 = b'qwaszxerdfcvtygh'
        p2 = b'QWASZXERDFCVTYGH'
        p3 = b'1234567891234560'
        c1 = s.encrypt(p1)
        c2 = s.encrypt(p2)
        c3 = s.encrypt(p3)
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!')
        self.assertEqual(s.decrypt(c1), p1)
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!',
                                            offset=16)
        self.assertEqual(s.decrypt(c2), p2)
        s = self.c.new_stream(b'Thirtytwo bytes key for AES-256!',
                                            b'Sixteen byte IV!',
                                            offset=32)
        self.assertEqual(s.decrypt(c3), p3)

if __name__ == '__main__':
    unittest.main()

