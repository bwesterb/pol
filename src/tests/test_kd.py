import unittest
import binascii

import pol.kd

class TestSHA(unittest.TestCase):
    def setUp(self):
        self.kd = pol.kd.KeyDerivation.setup()
    def test_default(self):
        self.assertEqual(self.kd.params['type'], 'sha')
    def test_restore(self):
        self.kd2 = pol.kd.KeyDerivation.setup(self.kd.params)
        self.assertEqual(self.kd2.params['salt'], self.kd.params['salt'])
        self.assertEqual(self.kd2(['abc']), self.kd(['abc']))
    def test_single_unsalted(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha', 'salt':''})
        self.assertEqual(binascii.hexlify(kd(['abc'])),
                        '4be9b856664b17f617ac8f072c48f80f'+
                        '6b008abb9f0499c2a5914b5683f3386f')
    def test_single(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt':'c'})
        self.assertEqual(binascii.hexlify(kd(['ab'])),
                        '530c455f8ff55d3d40bac27074c8f730'+
                        '8c7bd40e03808353e3296207ada91388')
    def test_multiple_salted(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt':'c'})
        self.assertEqual(binascii.hexlify(kd(['a', 'b', 'c'])),
                        'b87a32912e780ab8e22555d132fec8c0'+
                        '1b2867128ebb4e56dcac029e71ac902f')
    def test_multiple_unsalted(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt': ''})
        self.assertEqual(binascii.hexlify(kd(['a', 'b', 'c'])),
                        '0a8ffaf1c23bf0fa6e3a9cc1fa4ff914'+
                        '900213a45cba87d66d9d6c611dcf3cee')
    def test_short(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt':'c'})
        self.assertEqual(binascii.hexlify(kd(['a', 'b', 'c'], 13)),
                        'b87a32912e780ab8e22555d132')
    def test_double(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt':'c'})
        self.assertEqual(binascii.hexlify(kd(['a', 'b', 'c'], 64)),
                'b87a32912e780ab8e22555d132fec8c01b2867128ebb4e56dcac029e71ac9'+
                '02f9e6c49cc332427586fef3cd34330d2724494c09044f475b7c47c24774b'+
                '996059')
    def test_long(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt':'c'})
        self.assertEqual(binascii.hexlify(kd(['a', 'b', 'c'], 128)),
                'b87a32912e780ab8e22555d132fec8c01b2867128ebb4e56dcac029e71ac9'+
                '02f9e6c49cc332427586fef3cd34330d2724494c09044f475b7c47c24774b'+
                '996059a8fe87e36dde9c60b1e3838d5a891d023f58b73667672d3b796224e'+
                '6b7c617bb6b20a9c08b49f40f9b37f5f34be841e957e415638b6cc03cb4c5'+
                '2906044e65e5')


if __name__ == '__main__':
    unittest.main()

