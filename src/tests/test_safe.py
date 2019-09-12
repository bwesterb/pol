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
        safe._write_block(0, safe._eg_encrypt_block(
                        b'key', 0, b'123456789', randfunc, annex=True))
        self.assertEqual(safe._eg_decrypt_block(b'key', 0),
                        b'123456789'.ljust(safe.bytes_per_block, b'\0'))
        data = randfunc(safe.bytes_per_block)
        safe._write_block(0, safe._eg_encrypt_block(
                        b'key', 0, data, randfunc))
        self.assertEqual(safe._eg_decrypt_block(b'key', 0), data)
    def test_slice_store(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=10)
        sl = safe._new_slice(10)
        self.assertEqual(sl.size, 1224)
        self.assertRaises(pol.safe.WrongKeyError, sl.store, b'key', b'!'*sl.size)
        sl.store(b'key', b'!'*sl.size, annex=True)
        sl.store(b'key', b'!'*sl.size)
        self.assertRaises(ValueError, sl.store, b'key', b'!'*(sl.size+1))
        sl.store(b'key', b'!'*1)
        sl.store(b'key', b'')
    def test_find_slices(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=10)
        sl1 = safe._new_slice(2)
        sl2 = safe._new_slice(2)
        sl3 = safe._new_slice(2)
        sl1.store(b'key', b'!!!!', annex=True)
        sl2.store(b'key', b'!!!!', annex=True)
        sl3.store(b'key3', b'!!!!', annex=True)
        self.assertFalse(list(safe._find_slices(b'nokey')))
        self.assertEqual(len(list(safe._find_slices(b'key'))), 2)
    def test_load_slice(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=10)
        sl = safe._new_slice(5)
        sl.store(b'key', b'!!!!', annex=True)
        self.assertEqual(safe._load_slice(b'key', sl.first_index).value,
                            b'!!!!')
        randfunc = Crypto.Random.new().read
        sl.store(b'key', b'abcd'*(sl.size//4))
        self.assertEqual(safe._load_slice(b'key', sl.first_index).value,
                                b'abcd'*(sl.size//4))
        data = randfunc(sl.size)
        sl.store(b'key', data)
        self.assertEqual(safe._load_slice(b'key', sl.first_index).value, data)
    def test_large_slice(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        sl = safe._new_slice(70)
        randfunc = Crypto.Random.new().read
        data = randfunc(sl.size)
        sl.store(b'key', data, annex=True)
        self.assertEqual(safe._load_slice(b'key', sl.first_index).value, data)
    def test_open_containers(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        safe.new_container(b'm', b'l', b'a', nblocks=70)
        self._assert_no_open_containers(safe)

        cs_m = list(safe.open_containers(b'm'))
        self.assertEqual(len(cs_m), 1)
        c_m = cs_m[0]
        self.assertTrue(c_m.can_add)
        del(cs_m, c_m); self._assert_no_open_containers(safe)

        cs_l = list(safe.open_containers(b'l'))
        self.assertEqual(len(cs_l), 1)
        c_l = cs_l[0]
        self.assertTrue(c_l.can_add)
        del(cs_l, c_l); self._assert_no_open_containers(safe)

        cs_a = list(safe.open_containers(b'a'))
        self.assertEqual(len(cs_a), 1)
        c_a = cs_a[0]
        self.assertTrue(c_a.can_add)
        del(cs_a, c_a); self._assert_no_open_containers(safe)
    def test_additional_keys(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        safe.new_container(b'm', b'l', b'a', nblocks=30,
                                additional_keys=[b'b',b'a'])
        self._assert_no_open_containers(safe)

        cs_m = list(safe.open_containers(b'm'))
        self.assertEqual(len(cs_m), 0)
        del(cs_m); self._assert_no_open_containers(safe)
        cs_m = list(safe.open_containers(b'm', additional_keys=[b'a', b'b']))
        self.assertEqual(len(cs_m), 1)
        c_m = cs_m[0]
        self.assertTrue(c_m.can_add)
        del(cs_m, c_m); self._assert_no_open_containers(safe)

        cs_l = list(safe.open_containers(b'l'))
        self.assertEqual(len(cs_l), 0)
        del(cs_l); self._assert_no_open_containers(safe)
        cs_l = list(safe.open_containers(b'l', additional_keys=[b'a', b'b']))
        self.assertEqual(len(cs_l), 1)
        c_l = cs_l[0]
        self.assertTrue(c_l.can_add)
        del(cs_l, c_l); self._assert_no_open_containers(safe)

        cs_a = list(safe.open_containers(b'a'))
        self.assertEqual(len(cs_a), 0)
        del(cs_a); self._assert_no_open_containers(safe)
        cs_a = list(safe.open_containers(b'a', additional_keys=[b'a', b'b']))
        self.assertEqual(len(cs_a), 1)
        c_a = cs_a[0]
        self.assertTrue(c_a.can_add)
        del(cs_a, c_a); self._assert_no_open_containers(safe)

        self.assertEqual(len(list(safe.open_containers(b'm',
                        additional_keys=[b'a', b'b', b'c']))), 0)
        self.assertEqual(len(list(safe.open_containers(b'o',
                        additional_keys=[b'a', b'b']))), 0)

    def test_main_data(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        safe.new_container(b'm', b'l', None, nblocks=70)
        self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm'))[0]
        self._fill_container(c)
        self._check_container(c)
        c.save()
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm'))[0]
        self._check_container(c)
        self._check_container_secrets(c)
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'l'))[0]
        self._check_container(c)
        del(c); self._assert_no_open_containers(safe)
    def test_append_data(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        safe.new_container(b'm', b'l', b'a', nblocks=70)
        self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'a'))[0]
        self._fill_container(c)
        self.assertRaises(pol.safe.MissingKey, self._check_container, c)
        c.save()
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm', move_append_entries=False))[0]
        self._check_container(c)
        self._check_container_secrets(c)
        c.save()
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'l', move_append_entries=False))[0]
        self.assertEqual(len(list(c.list())), 0)
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm'))[0]
        self._check_container(c)
        self._check_container_secrets(c)
        c.save()
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'l', move_append_entries=False))[0]
        self._check_container(c)
    def test_removal(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        safe.new_container(b'm', b'l', b'a', nblocks=70)
        self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'a'))[0]
        self._fill_container(c)
        c.save()
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm', move_append_entries=False))[0]
        list(c.get('key1'))[0].remove()
        list(c.get('key2'))[0].remove()
        c.save()
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm'))[0]
        list(c.get('key3'))[0].remove()
        list(c.get('key4'))[0].remove()
        list(c.get('key4'))[0].remove()
        c.save()
        del(c); self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm'))[0]
        self.assertEqual(len(c.list()), 0)
        del(c); self._assert_no_open_containers(safe)
    def test_opening_containers_again(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        safe.new_container(b'm', b'l', b'a', nblocks=70)
        self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'a'))[0]
        c2 = list(safe.open_containers(b'a'))[0]
        self.assertTrue(c is c2)
        self.assertFalse(c.has_secrets)
        self.assertRaises(pol.safe.MissingKey, c2.list)
        del(c2)
        c2 = list(safe.open_containers(b'l'))[0]
        self.assertTrue(c2 is c)
        self.assertEqual(c2.list(), [])
        self.assertFalse(c.has_secrets)
        del(c2)
        c2 = list(safe.open_containers(b'm'))[0]
        self.assertTrue(c2 is c)
        self.assertTrue(c.has_secrets)
    def test_autosave(self):
        safe = pol.safe.Safe.generate(precomputed_gp=True, n_blocks=70)
        safe.new_container(b'm', b'l', b'a', nblocks=70)
        self._assert_no_open_containers(safe)
        c = list(safe.open_containers(b'a'))[0]
        self._fill_container(c)
        del(c)
        self._assert_no_open_containers(safe)

        c = list(safe.open_containers(b'm'))[0]
        self._check_container(c)
        self._check_container_secrets(c)
    def _assert_no_open_containers(self, safe):
        ok = True
        for ref in safe._opened_containers.values():
            if ref():
                ok = False
                break
        self.assertTrue(ok)
    def _fill_container(self, c):
        c.add('key1', 'note1', 'secret1')
        c.add('key2', 'note2', 'secret2')
        c.add('key3', 'note3', 'secret3')
        c.add('key4', 'note4', 'secret4')
        c.add('key4', 'note4', 'secret4')
    def _check_container_secrets(self, c):
        self.assertEqual(list(c.get('key1'))[0].secret, 'secret1')
        self.assertEqual(list(c.get('key2'))[0].secret, 'secret2')
        self.assertEqual(list(c.get('key3'))[0].secret, 'secret3')
        self.assertEqual(list(c.get('key4'))[0].secret, 'secret4')
        self.assertEqual(list(c.get('key4'))[1].secret, 'secret4')
    def _check_container(self, c):
        self.assertEqual(len(list(c.get('key1'))), 1)
        self.assertEqual(len(list(c.get('key2'))), 1)
        self.assertEqual(len(list(c.get('key3'))), 1)
        self.assertEqual(len(list(c.get('key4'))), 2)
        self.assertEqual(list(c.get('key1'))[0].key, 'key1')
        self.assertEqual(list(c.get('key2'))[0].key, 'key2')
        self.assertEqual(list(c.get('key3'))[0].key, 'key3')
        self.assertEqual(list(c.get('key4'))[0].key, 'key4')
        self.assertEqual(list(c.get('key4'))[1].key, 'key4')
        self.assertEqual(list(c.get('key1'))[0].note, 'note1')
        self.assertEqual(list(c.get('key2'))[0].note, 'note2')
        self.assertEqual(list(c.get('key3'))[0].note, 'note3')
        self.assertEqual(list(c.get('key4'))[0].note, 'note4')
        self.assertEqual(list(c.get('key4'))[1].note, 'note4')


if __name__ == '__main__':
    unittest.main()

