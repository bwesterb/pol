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
                                        'aa26bc0f386aa09ab2d867d2aac7507a')
        self.assertEqual(binascii.hexlify(s.encrypt('1234567890123456')),
                                        'c192580459cc1fa9b03c3ee7babe93dd')
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(binascii.hexlify(s.encrypt('1234567890123456'*2)),
                                        'aa26bc0f386aa09ab2d867d2aac7507a'+
                                        'c192580459cc1fa9b03c3ee7babe93dd')
    def test_decrypt(self):
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            'aa26bc0f386aa09ab2d867d2aac7507a')),
                            '1234567890123456')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            'c192580459cc1fa9b03c3ee7babe93dd')),
                            '1234567890123456')
        s = self.c.new_stream('Thirtytwo bytes key for AES-256!',
                                            'Sixteen byte IV!')
        self.assertEqual(s.decrypt(binascii.unhexlify(
                            'aa26bc0f386aa09ab2d867d2aac7507a'+
                            'c192580459cc1fa9b03c3ee7babe93dd')),
                            '1234567890123456'*2)

if __name__ == '__main__':
    unittest.main()

