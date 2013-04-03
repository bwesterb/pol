import unittest
import tempfile

import pol.main

class TestMain(unittest.TestCase):
    def setUp(self):
        self.safe = tempfile.NamedTemporaryFile()
        self.pol('init', '-P', '-p', 'a', 'b', 'c', '-f')

    def pol(self, *args):
        ret = pol.main.entrypoint(['-s', self.safe.name] + list(args))
        if ret is None:
            return 0
    def test_touch(self):
        self.assertEqual(self.pol('touch'), 0)
    def test_raw(self):
        self.assertEqual(self.pol('raw'), 0)
    def test_list(self):
        self.assertEqual(self.pol('list', '-p', 'a'), 0)
        self.assertEqual(self.pol('list', '-p', 'b'), 0)

if __name__ == '__main__':
    unittest.main()

