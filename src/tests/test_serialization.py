import unittest

import pol.serialization

import gmpy2

class TestSerialization(unittest.TestCase):
    def test_number_to_string_and_back(self):
        rnd = gmpy2.random_state()
        for i in range(100):
            x = gmpy2.mpz_random(rnd, 2**4096)
            x2 = pol.serialization.string_to_number(
                    pol.serialization.number_to_string(x))
            self.assertEqual(x, x2)
    def test_son_to_string_and_back(self):
        tests = [
            {b'a': [b'q', b'a', 12345]}
        ]
        for x in tests:
            x2 = pol.serialization.string_to_son(
                    pol.serialization.son_to_string(x))
            self.assertEqual(x, x2)

if __name__ == '__main__':
    unittest.main()

