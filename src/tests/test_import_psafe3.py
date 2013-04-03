import unittest
import binascii
import cStringIO as StringIO

from datetime import datetime
from uuid import UUID

import pol.importers.psafe3

TEST_SAFE = binascii.unhexlify(
            '50575333beba983fe53bba4e9a4bd6f034c10ae9f1188851e24de849c4681bbc9'+
            'ea247a600080000e715186951378d4e53ccf32a468139df42a1a573cb3c9440d9'+
            '331a1f9543cf5b451d05c51d2f1c489b5a6281a5f10e4bb739cc0a4a524298359'+
            '13dfae889e1174e6bd22a423e9df7b81fb4ea1ea20a8a7597fc3455f5b6f68825'+
            'ce2bf6b566fcaf3ae452a229fe0442a053468019914de6c02c9bdc7c23558c3da'+
            '440ee2b8ee12f639bf782bf02b0460b52c519bcc80241ff2d301bd000e0c56f40'+
            '56a34fce85548616411d1a5ca77a26f4ed0415a5acea3a64188e4593357c84134'+
            '353c6bf283a45dde69d72f35cefc36791d822386d0d7b6275cb529422cd94a39a'+
            '1f4622487882a90b1f4d9c9c714cd5081508da46c82b2f2e3803b49bba8ef2ceb'+
            '4798ad9ec5ca6af477fe60dcb0d66e3e8a68c47898cdb1b1acccd8a57aa6be020'+
            '88f368d90e32dfc94e4587e7e97739c8b33e3a229cb9b2d3f9a4465b1e8f3943c'+
            '578b02ecab77a4b683c8e02a0dfa632d1c136479cac4fa002a55fe7f75a2af8a8'+
            '670c09bb72d2bf2c57e02c222280d797dceb092be54586df8cc8329afba756acf'+
            '45905f1b2cb9ba2166d9ce1110ef582bcb95b5909bb5fc4c8cdc049bb4775d470'+
            '71a95faa970c71ae24f8e23e50239ff53a94c4a357f4c472f9259075a9e2d4172'+
            '66240e5d935bd958fc9dbeffa87fe5c0225aceb234c23c2187218d8de82eb9ccd'+
            'c14044cc6fded92eea1832511d0ea58c0b610faf15f5f57697528921847eda438'+
            '0f35b514a5b2f09a69c93a7e8de117b608338f1bdbca5dc1c8788b0a185596b36'+
            '99fbd7162b444bfc551fda4894a7440c0affef4be9905c16a3eb03e9d219877c2'+
            '1a6f3d98ff5d171c47870340a1deb649874d2b315fabfeed2e8283a55907edd0d'+
            '112015af2bc5b63cc1057bcc2a5681afde403452a31b800fcaecf55c11b0982b0'+
            'ac0516f5be25782dda2deed306cbe287ce5588d9b7e118536cd400f8372fe6309'+
            'e66c8dc50abbecad78570fadc3b1b08ea321fa1591c682c8252418d10dfdc5ac9'+
            '1311cf811f157173c48daba71e4e19624878f998431dd9b1845748dd0886dba89'+
            '428ff0750b17284ca8a79f8037870f42812f574c033c68bcc8373b8bebc1940c7'+
            '538c78a3f445fdf60bc62f1f9ac31f16e6767cea5863f3597bae67b6fc665289c'+
            '68369a38e367f71da0167eed9a71f67d72c8e744d0aacca44239fd2d4dfc6da32'+
            '956d1a35d64b385bdae6187f562e966acd041a8895ce96254980fca8cb0a1cf0f'+
            'a5e514a5c0c09319719c9b387514788a1ff17167c33790266ce3a4bf9060f3f08'+
            '9c0ce5de9a57e5650586606b7fb4571f811f0ad22a85a14620e1f9a073bed112b'+
            '27250cbebdf4d608384d310b5b7647b1722ee5186d62322f58fb44a779ca089f7'+
            '68d6848d310b9aff9e6317883397c57a2e3f755a52c1d00da006daac522c461f2'+
            '5da8fbaad3ad7c6abf5be8a4bba2c6b635d222d27e719a86458cfd111baf575b0'+
            'e6fe5cd8ede94bf0038369942e55da2e80c24a82b9470e4f1083fb4fdcb3950bb'+
            'e5bbbca7e7ee9b0925e17989ca902832388ee2129739e29232a633392906302dd'+
            'dc2e40286eb7142abab26cc209ab1e8e131119168e1df78df8a72706279c0a516'+
            '0d6d0189a1066b720d7af44861195bc51a0a0d25a592eddb862623c3628c2507e'+
            '9983b7848a8505753332d454f46505753332d454f46bd438aec1bdbe3a2d06b8c'+
            '16141f15e29ce198eaca94ba837e6e526ffdf3379c')

class TestPSafe3(unittest.TestCase):
    def test_psafe3_wrong_password(self):
        self.assertRaises(pol.importers.psafe3.BadPasswordError,
                          pol.importers.psafe3.load,
                          StringIO.StringIO(TEST_SAFE), 'wrong password')
    def test_psafe3_integrity(self):
        s = TEST_SAFE
        s = s.replace('a', 'b')
        self.assertRaises(pol.importers.psafe3.IntegrityError,
                          pol.importers.psafe3.load,
                          StringIO.StringIO(s), 'test')
    def test_psafe3_load(self):
        self.assertEqual(pol.importers.psafe3.load(StringIO.StringIO(TEST_SAFE),
                            'test'),
            ({'last-save': datetime.fromtimestamp(1364980310),
              'last-save-by-user': 'bas',
              'last-save-on-host': 'emma.lan',
              'last-save-what': '',
              'non-default-preferences': '',
              'uuid': UUID('0410f88d-0e77-4fed-918c-4a0b2c51fb44'),
              'version': 779},
             [{'group': 'group.sub group',
               'password': '[G2&#oRpAWVF',
               'password-modification-time': datetime.fromtimestamp(1364980257),
               'title': 'testing',
               'username': 'user',
               'uuid': UUID('1d0ace17-b4d0-42a9-89b1-d5144b4878e3')},
              {'group': 'group',
               'notes': 'this is a note',
               'password': '(?E[7bET-7zi',
               'password-modification-time': datetime.fromtimestamp(1364980249),
               'title': 'another test',
               'username': '',
               'uuid': UUID('1ed6b055-d0b1-c377-caac-c51bad0ae6d0')},
              {'password': '%-|lez&h\\6tO',
               'password-modification-time': datetime.fromtimestamp(1344544417),
               'title': 'Hallo',
               'url': 'omg',
               'username': 'wee',
               'uuid': UUID('47b93810-5d66-fcb0-8df1-c3e1ceb52487')},
              {'email-address': 'waa@mail.com',
               'group': 'group',
               'notes': 'RARA',
               'password': 'G!?1[9I~u<,M',
               'password-modification-time': datetime.fromtimestamp(1344544429),
               'title': 'Wee',
               'url': 'woo',
               'username': 'waa',
               'uuid': UUID('494d920b-3633-18ab-31cc-b3a8193d1633')},
              {'email-address': 'wee',
               'group': 'group.sub group',
               'notes': 'wee',
               'password': ':9cUzL[lq?}?',
               'password-modification-time': datetime.fromtimestamp(1344544437),
               'title': 'title',
               'url': 'wee',
               'username': 'lol',
               'uuid': UUID('d2e56e7d-c84f-5604-554f-ba63e3d943db')}]))
    def test_psafe3_import(self):
        pass

if __name__ == '__main__':
    unittest.main()

