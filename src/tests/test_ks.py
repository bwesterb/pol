import unittest
import binascii

import pol.ks

class TestSCrypt(unittest.TestCase):
    def setUp(self):
        self.ks = pol.ks.KeyStretching.setup()
    def test_default(self):
        self.assertEqual(self.ks.params['type'], 'scrypt')
        self.assertEqual(binascii.hexlify(
                self.ks.derive('waasdasdada', 'waasdasdaa')),
                            '69e9b3dafbc7cbe8d903fb1e6e1633da6c45fcd3f6e'+
                            'df66d34532a2883a7abd9390bbc834020a0539d8304'+
                            '570ee7b9eb64ab00ecad1bbd89e1a93c2c38646581')

if __name__ == '__main__':
    unittest.main()

