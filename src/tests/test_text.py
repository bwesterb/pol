import unittest

import pol.text

class TestText(unittest.TestCase):
    def test_escape_cseqs(self):
        pairs = (
            (u'test', u'test'),
            (u'te\nst', u'te\\nst'),
            (u'Jedenfalls bin ich \xfcberzeugt, dass der'+
                u' [Herrgott] nicht w\xfcrfelt.',
             u'Jedenfalls bin ich \xfcberzeugt, dass der'+
                u' [Herrgott] nicht w\xfcrfelt.'))
        for inp, outp in pairs:
            self.assertEqual(pol.text.escape_cseqs(inp.encode('utf-8')),
                                outp.encode('utf-8'))
        self.assertEqual(pol.text.escape_cseqs('\xf4'), '\\xf4')

if __name__ == '__main__':
    unittest.main()

