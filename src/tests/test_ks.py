import unittest
import binascii

import pol.ks

class TestSCrypt(unittest.TestCase):
    def setUp(self):
        self.ks = pol.ks.ScryptKeyStretching.setup()
    def test_restore(self):
        self.ks2 = pol.ks.KeyStretching.setup(self.ks.params)
        self.assertEqual(self.ks2.params[b'salt'], self.ks.params[b'salt'])
        self.assertEqual(self.ks2(b'abc'), self.ks(b'abc'))
    def test_value(self):
        ks = pol.ks.KeyStretching.setup({
                b'type': b'scrypt', b'Nexp': 15, b'salt': b'waasdasdaa'})
        self.assertEqual(binascii.hexlify(
                ks.stretch(b'waasdasdada')),
                            b'69e9b3dafbc7cbe8d903fb1e6e1633da6c45fcd3f6e'+
                            b'df66d34532a2883a7abd9390bbc834020a0539d8304'+
                            b'570ee7b9eb64ab00ecad1bbd89e1a93c2c38646581')

class TestArgon2(unittest.TestCase):
    def setUp(self):
        self.ks = pol.ks.KeyStretching.setup()
    def test_default(self):
        self.assertEqual(self.ks.params[b'type'], b'argon2')
        self.assertEqual(self.ks.params[b't'], 1)
        self.assertEqual(self.ks.params[b'm'], 102400)
        self.assertEqual(self.ks.params[b'p'], 4)
    def test_restore(self):
        self.ks2 = pol.ks.KeyStretching.setup(self.ks.params)
        self.assertEqual(self.ks2.params[b'salt'], self.ks.params[b'salt'])
        self.assertEqual(self.ks2(b'abc'), self.ks(b'abc'))
    def test_value_v10(self):
        ks = pol.ks.KeyStretching.setup({
            b'type': b'argon2', b't': 1, b'm':8, b'p':1, b'salt': b'waasdasdaa'})
        self.assertEqual(binascii.hexlify(
                ks.stretch(b'waasdasdada')),
                            b'16a0a8427be8fe5a1ecce6b03ef9607a1d4064168e1'+
                            b'94af4c13652af8a1728f8c4acc59d0cabe7159104de'+
                            b'737165f6c646d912307bbfa9db11adab00bdaabf4b')
    def test_value_v13(self):
        ks = pol.ks.KeyStretching.setup({
            b'type': b'argon2', b't': 1, b'm':8, b'p':1, b'salt': b'waasdasdaa',
            b'v':0x13})
        self.assertEqual(binascii.hexlify(
                ks.stretch(b'waasdasdada')),
                   (b'96f5ba079ff69cb9a0eecc16399a2d12fab4d7b7fd1591c1b5b14d59c9'
                    b'498a7f9598c6912d970ca7db619177cc22be83996bdf5a480a346c33c8'
                    b'857e7578fc61'))

if __name__ == '__main__':
    unittest.main()

