import unittest
import functools

import pol.elgamal

import gmpy

class TestGroupParametersBase(unittest.TestCase):
    def _test_gp(self, gp, bits):
        q = (gp.p - 1) / 2
        self.assertTrue(gmpy.is_prime(gp.p))
        self.assertTrue(gmpy.is_prime(q))
        self.assertTrue(2**(bits-1) < gp.p)
        self.assertTrue(gp.p < 2**bits)
        self.assertTrue(gp.g < gp.p)
        self.assertTrue(3 < gp.g)
        self.assertNotEqual(pow(gp.g, 2, gp.p), 1)
        self.assertNotEqual(pow(gp.g, q, gp.p), 1)
        self.assertNotEqual(divmod(gp.p, gp.g)[1], 0)
        ginv = gmpy.invert(gp.g, gp.p)
        self.assertNotEqual(divmod(gp.p - 1, ginv)[1], 0)

class TestPrecomputedGroupParameters(TestGroupParametersBase):
    def _test_precomputed_parameters(self, bits):
        self._test_gp(pol.elgamal.precomputed_group_params(bits), bits)
for bits in (1025, 2049, 4097):
    def ch(bits): return lambda self: self._test_precomputed_parameters(bits)
    setattr(TestPrecomputedGroupParameters, 'test_%s' % bits, ch(bits))

class TestGeneratedGroupParameters(TestGroupParametersBase):
    def _test_generated_group_parameters(self, bits):
        gp = pol.elgamal.generate_group_params(bits)
        self._test_gp(gp, bits)
for bits in (128, 256, 512):
    def ch(bits):
        return lambda self: self._test_generated_group_parameters(bits)
    setattr(TestGeneratedGroupParameters, 'test_%s' % bits, ch(bits))

if __name__ == '__main__':
    unittest.main()

