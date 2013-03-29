import unittest
import binascii

import pol.progressbar

class TestProgressBar(unittest.TestCase):
    def test_normal(self):
        with pol.progressbar.ProgressBar() as p:
            for i in xrange(100):
                p(i/100.0)
    def test_probablistic(self):
        with pol.progressbar.ProbablisticProgressBar() as p:
            for i in xrange(100):
                p(pol.progressbar.coin(0.005, i))

if __name__ == '__main__':
    unittest.main()

