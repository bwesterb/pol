import unittest
import tempfile

import pol.main

class TestMain(unittest.TestCase):
    def setUp(self):
        self.safe = tempfile.NamedTemporaryFile()
        self.config = tempfile.NamedTemporaryFile()

    def pol(self, *args):
        ret = pol.main.entrypoint(['-s', self.safe.name,
                                   '-C', self.config.name] + list(args))
        return 0 if ret is None else ret
    def test_basic(self):
        # TODO we should check output
        self.pol('init', '-P', '-p', 'a', 'b', 'c', '-f',
                    '--i-know-its-unsafe', '-N', '128')
        self.assertEqual(self.pol('list', '-p', 'a'), 0)
        self.assertEqual(self.pol('list', '-p', 'b'), 0)
        self.assertEqual(self.pol('put', '-p', 'a', '-s', 'a secret', 'key'), 0)
        self.assertEqual(self.pol('get', '-p', 'a', 'key'), 0)
        self.assertEqual(self.pol('put', '-p', 'b', '-s', 'a secret', 'key'), 0)
        self.assertEqual(self.pol('put', '-p', 'c', '-s', 'a secret', 'key'), 0)
        self.assertEqual(self.pol('put', '-p', 'd', '-s', 'a secret', 'key'), -1)
        self.assertEqual(self.pol('get', '-p', 'a', 'key'), -8)
        self.assertEqual(self.pol('get', '-p', 'b', 'key'), -4)
        self.assertEqual(self.pol('get', '-p', 'c', 'key'), -4)
        self.assertEqual(self.pol('list', '-p', 'a'), 0)
        self.assertEqual(self.pol('list', '-p', 'b'), 0)
        self.assertEqual(self.pol('touch'), 0)
        self.assertEqual(self.pol('export', '-p', 'a'), 0)
    def test_cracktime_names(self):
        self.assertEqual(frozenset(pol.main.cracktime_names),
                         frozenset(pol.main.cracktimes.keys()))


if __name__ == '__main__':
    unittest.main()

