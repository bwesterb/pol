import unittest

import pol.editfile

class TestEditfile(unittest.TestCase):
    def test_issue7(self):
        orig = {0: [('key' + str(i),
                         'secret' + str(i),
                         'note' + str(i) if i % 2 == 0  else None)
                                for i in xrange(158)]}
        dumped = pol.editfile.dump(orig)
        parsed = pol.editfile.parse(dumped, orig.keys(), {})
        self.assertEqual(orig, parsed)

    def test_multContainers(self):
        orig = {0: [('key' + str(i),
                         'secret' + str(i),
                         'note' + str(i) if i % 2 == 0  else None)
                                for i in xrange(10)],
                1: [('key' + str(i),
                         'secret' + str(i),
                         'note' + str(i) if i % 2 == 0  else None)
                                for i in xrange(10)],
                2: [('key' + str(i),
                         'secret' + str(i),
                         'note' + str(i) if i % 2 == 0  else None)
                                for i in xrange(10)]}
        dumped = pol.editfile.dump(orig)
        parsed = pol.editfile.parse(dumped, orig.keys(), {})
        self.assertEqual(orig, parsed)

    def test_spaces(self):
        self.assertEqual(pol.editfile.parse("""
                CONTAINER 2
                a #3 "test test"
                b "secret" a longer note

                CONTAINER 3
                "a key with a space" "sekrit with space" "note with quotes"
                """, [2, 3], {3: 'secret 3'}),
                    {2: [('a', 3, 'test test'),
                         ('b', 'secret', 'a longer note')],
                     3: [('a key with a space', 'sekrit with space',
                             'note with quotes')]})
    def test_emptyContainer(self):
        self.assertEqual(pol.editfile.parse("""
                CONTAINER 1
                """, [1], {}), {1: []}) 
    def test_emptyFile(self):
        self.assertEqual(pol.editfile.parse("""
                """, [], {}), {}) 
    def test_quotes(self):
        orig = {0: [('"', '"', '"'),
                    ('\\"', '\\', '\\\\'),
                    ('a b', 'c d \\\\"', '" hi "')]}
        dumped = pol.editfile.dump(orig)
        parsed = pol.editfile.parse(dumped, orig.keys(), {})
        self.assertEqual(orig, parsed)

if __name__ == '__main__':
    unittest.main()

