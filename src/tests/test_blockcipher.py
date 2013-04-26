import unittest
import binascii

import pol.blockcipher

class TestAES(unittest.TestCase):
    def setUp(self):
        self.c = pol.blockcipher.BlockCipher.setup()
    def test_default(self):
        self.assertEqual(self.c.params['type'], 'aes')
        self.assertEqual(self.c.params['bits'], 256)
    def test_encrypt(self):
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(binascii.hexlify(s.encrypt('1234567890123456')),
                                        '6cef07fd1ac23d4b6f7429871bb99d8e')
        self.assertEqual(binascii.hexlify(s.encrypt('1234567890123456')),
                                        '2f3f54eba982349b503152c6ec848886')
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(binascii.hexlify(s.encrypt('1234567890123456'*2)),
                                        '6cef07fd1ac23d4b6f7429871bb99d8e'+
                                        '2f3f54eba982349b503152c6ec848886')
    def test_decrypt(self):
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            '6cef07fd1ac23d4b6f7429871bb99d8e')),
                            '1234567890123456')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            '2f3f54eba982349b503152c6ec848886')),
                            '1234567890123456')
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            '6cef07fd1ac23d4b6f7429871bb99d8e'+
                            '2f3f54eba982349b503152c6ec848886')),
                            '1234567890123456'*2)
    def test_offset(self):
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        p1 = 'qwaszxerdfcvtygh'
        p2 = 'QWASZXERDFCVTYGH'
        p3 = '1234567891234560'
        c1 = s.encrypt(p1)
        c2 = s.encrypt(p2)
        c3 = s.encrypt(p3)
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(s.decrypt(c1), p1)
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!',
                                            offset=16)
        self.assertEqual(s.decrypt(c2), p2)
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!',
                                            offset=32)
        self.assertEqual(s.decrypt(c3), p3)

if __name__ == '__main__':
    unittest.main()

