import unittest

import Crypto.Random

import pol.safe

class TestElgamalSafe(unittest.TestCase):
    def test_generate(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True)
    def test_new_slice(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=100)
        safe._new_slice(100)
    def test_new_slice_full(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=100)
        self.assertRaises(pol.safe.SafeFullError, safe._new_slice, 101)
    def test_elgamal(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=1)
        randfunc = Crypto.Random.new().read
        safe._eg_encrypt_block('key', 0, '123456789', randfunc, annex=True)
        self.assertEqual(safe._eg_decrypt_block('key', 0),
                        '123456789'.ljust(safe.bytes_per_block, '\0'))
        data = randfunc(safe.bytes_per_block)
        safe._eg_encrypt_block('key', 0, data, randfunc)
        self.assertEqual(safe._eg_decrypt_block('key', 0), data)
    def test_slice_store(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=10)
        sl = safe._new_slice(10)
        self.assertEqual(sl.size, 1224)
        self.assertRaises(pol.safe.WrongKeyError, sl.store, 'key', '!'*sl.size)
        sl.store('key', '!'*sl.size, annex=True)
        sl.store('key', '!'*sl.size)
        self.assertRaises(ValueError, sl.store, 'key', '!'*(sl.size+1))
        sl.store('key', '!'*1)
        sl.store('key', '')
    def test_find_slice(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=10)
        sl = safe._new_slice(10)
        sl.store('key', '!!!!', annex=True)
        self.assertEqual(safe._find_slice('nokey'), -1)
        self.assertEqual(safe._find_slice('key'), sl.first_index)

if __name__ == '__main__':
    unittest.main()

