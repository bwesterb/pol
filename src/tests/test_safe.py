import unittest
import tempfile

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
    def test_slice_store(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=10)
        sl = safe._new_slice(10)
        self.assertEqual(sl.size, 1240)
        self.assertRaises(pol.safe.WrongKeyError, sl.store, 'key', '!'*sl.size)
        sl.store('key', '!'*sl.size, annex=True)
        sl.store('key', '!'*sl.size)
        self.assertRaises(ValueError, sl.store, 'key', '!'*(sl.size+1))
        sl.store('key', '!'*1)
        sl.store('key', '')
    def test_slice_load(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=10)
        sl = safe._new_slice(10)

if __name__ == '__main__':
    unittest.main()

