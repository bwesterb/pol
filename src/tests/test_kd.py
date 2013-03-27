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
        self.assertEqual(self.kd2.single('abc'), self.kd.single('abc'))
    def test_single_unsalted(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha', 'salt':''})
        self.assertEqual(binascii.hexlify(kd.single('abc')),
                        'ba7816bf8f01cfea414140de5dae2223'+
                        'b00361a396177a9cb410ff61f20015ad')
    def test_single(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt':'c'})
        self.assertEqual(binascii.hexlify(kd.single('ab')),
                        'ba7816bf8f01cfea414140de5dae2223'+
                        'b00361a396177a9cb410ff61f20015ad')
    def test_multiple_unsalted(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt': ''})
        self.assertEqual(binascii.hexlify(kd.multiple('a', 'b', 'c')),
                        '3a050f1d08fb8581d3d72ae727651e98'+
                        '1043de0d6ca8e744328758f716602beb')
    def test_multiple_unsalted(self):
        kd = pol.kd.KeyDerivation.setup({'bits': 256, 'type': 'sha','salt':'c'})
        self.assertEqual(binascii.hexlify(kd.multiple('a', 'b', 'c')),
                        'b9f78953508d32d6fa6ad7de56f578a5'+
                        '611391832f8b5278d8d6571ebb5f1f7a')

if __name__ == '__main__':
    unittest.main()

