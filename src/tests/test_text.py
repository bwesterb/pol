import unittest

import pol.text

class TestText(unittest.TestCase):
    def test_escape_cseqs(self):
        pairs = (
            ('test', 'test'),
            ('te\nst', 'te\\nst'),
            ('Jedenfalls bin ich \xfcberzeugt, dass der'+
               ' [Herrgott] nicht w\xfcrfelt.',
             'Jedenfalls bin ich \xfcberzeugt, dass der'+
                ' [Herrgott] nicht w\xfcrfelt.'))
        for inp, outp in pairs:
            self.assertEqual(pol.text.escape_cseqs(inp), outp)
        self.assertEqual(pol.text.escape_cseqs('\xf4'), '\xf4')

if __name__ == '__main__':
    unittest.main()

