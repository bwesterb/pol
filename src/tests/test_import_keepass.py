import unittest
import binascii
import cStringIO as StringIO

from datetime import datetime
from uuid import UUID

import pol.importers.keepass

TEST_DB1 = binascii.unhexlify(
        '03d9a29a65fb4bb50300000002000300c83b3bb81fe01cf52309af81cf4ce87c7b5ee'+
        '58f2b5959b2837f9512851c6b5d0100000003000000a3619df5674c826c37906a68a5'+
        '9efbcb3ff5a9967b91ff37d830b668810b82adad5cadc2b4ea4a357b0e72667438087'+
        '9e677361207314925f0bd910d6c428e5550c30000c6c02da3a2be18cd1921571cd832'+
        '144639ca31f4fff40f40bf43b95969d65f20c0e9e390c12a0df16bc612ba701288446'+
        '23780575ebfcab3222ceee9c26eebe0db7962ba4b954d7239ecdee7abdf177f6f3706'+
        '4cd964fd3627400cff2ac5cbc41291599da5efc53f47a2a2cca7a112f432a139d47fe'+
        'f084383f65bf16c67e886e7e84816e70d3ea50eae7add22c6ebbf5acd0da89ad053e8'+
        'd8e6a0ed960cfcc8fe16d9aa6285c4af729abddc6d81ac816051364012316416f0cd9'+
        'd3dd1e01df4571359e12b79c2067c8a8796781075240e7b88119e6d4069a40d7591e6'+
        '9375bc67561be401092c4b765495bde691becf0b9be0212ea81a780bd964fef249051'+
        '0d2417c6123c3e34b23b5c01e71d1df873ab976f6f99d8d1545563ec3df4d92312a3b'+
        '6b88f9297ed2d252832abd7c60e2c6eb64089e9a5022f529bbb15aa438f9a6faaeea2'+
        '2b0a93730d6c3adfcfdf9d26fc50548cec1b34714bae0e0cb4687d6761dbdafef374a'+
        'cd6885f21f248148f9d6bd825637ac0b58432fbf8b68498d75e4eef76452e0be806dc'+
        '84de7a040fe4f744a78dbca166f74b7c8c461f4d77d49454d19d2bb673d1b4fb076d6'+
        '6cd8846c2040c53202382a491e83980d4a28d1e78c5d6035cb1ac9a1d53a7d48aed2e'+
        'efe3af88f9eaa45db716b15121b35c16aa4fa209ecea6a615c83000de0e62ee943760'+
        '95b7f8b75ee300570efbfe976bef36c689c3cf49e37fca5fd2de8e05738418c1ca408'+
        'c3637536bf6633b6ff01dd8e959243d8bca45e8e4e3a2b31449bfc8c076f60e5eadc9'+
        'b71fff32ffc60e503ff45e0add0532c3d337250cbd93dba89f1c3db82580411901e46'+
        'ff9a6985b071baa8b8b986016337bdc909a6e13e9bb7fe82f34509f43da5f4840c6ce'+
        '748f06e4699f6fcd092da9d60bfd7c0d9b8bea6ab4a35e93083556585152a2c2e212e'+
        '0d2f4')
TEST_DB2 = binascii.unhexlify(
        '03d9a29a65fb4bb503000000020003007ef2b194ce81834530d7aa42e216061f13dbb'+
        '9b9da036d9362e62653ffc8e3fb0300000008000000107e441d625e04f89306e91d18'+
        'ae677e8c0099c79a415c22c84ba3c2d76e32bb199b98c5c4a9e75d8feca1cdce12d90'+
        '7be56b58fb9907d8cf82a2d8f1eac9c6650c3000054521f6031edadcc533c5208c7f4'+
        '5a771204972ebde82c4380d6122c658d5f36d5d6f26f23d98349a0c5d798f61c06df4'+
        '5ac34abf9d147ebdbc10fa6b0bce48e85d5b8f9cfb9fb9dfbc536061a7a4380c46217'+
        '8d829e039f2fd001e098f256b91f46bb00aca7687638809a058199a834fbd28a8e97c'+
        'ff5f6b9db19f8a922069b4cf289f7960802c8aa7abd67b5232bef2864e6a7047e4c6c'+
        'a991d067ac5f139756a08ae8220bdf17f4d27b8bce467a751cde5903cddd39e608e5c'+
        'cd869db1daf53653bb513575f939a987d01fc4d070711b2d5e69310253dfc9c46cb7e'+
        '6789a694e894bfde728f28c93365d5e73d2bd5bde6e4c8ff70de32f8b10e0aeef14c4'+
        'e19e9124bab703029cbd1ba2db3e08780ad0af668ac0fa6444756563262390fd66dc5'+
        'd2dc39c6d39ba0ada163371cb94dc30026c999cc4e1e2e24a594309a2eafc0fc26b3e'+
        'e0e11f6b666a6a8c5169107c6b01a8a244785a3aa9e26b2958bbcd8bd3d6bf93cce19'+
        '010fb69b17042ef2f36a9eecf0c50270bb14d4ee9097b9623d87ceedeb26dca7ddf7b'+
        'fbb02e4dd99ca8f4847688f7433e767286e19a34a480e49413831d68ade1b5fc15f17'+
        '7c7ccf898e55b38f88d25b86ce00a4d4cf4bdff04b4372e88086455b1dc106f1179ff'+
        'd871141d1856447dccc8d5f2a1a56c8e9ceee259a3317a46a70aaabb6b9dac8e58ec5'+
        '3c465575ffc2bd8f32a2d22986a1b6f823e6cef9e18fd2394a36bdb829dc4d29465f9'+
        'fd7522be32ac7bcf0521f3ae02ad20e2962d477ec83bc33e59ed2f80f32a2a4c068e2'+
        '30dc855bb82767ca0d48da22b846f20ccacf3ae81b3e42e1f8b2b4dd36d6adfd67c56'+
        '042b8ca60c5f2397646e417383533f1444a5c16b0089f63ff9156b451431eeca33d10'+
        'b2504921fbb2fb20f6a1bf2f1ac494a9fd46729c4be290531327ff3eefca00a2cadc4'+
        '263ce366563a6c187bd7e86e6017d610b8f5924569e5d52d354763d8e17143d1a8f2d'+
        'cd3966e4eaf2b1fe728e322df6ab0eb38650811d47ccced021f6d2fa3fe807a075c6f'+
        '206ad95e8cdb3558bc757da8e9571080f3c1dcc7075ee17795f4e95b43352e105a23d'+
        'cb28589bf0b97d63751b6afa078f0ab500e2c407603cefaf233225ab28fb3ba74cbac'+
        '06f45381a10819d025a1ab93ab09b8c21efadd0bfca52b4e235a6dfc4b208babacd4a'+
        'e61b28b6bb80362330a7949aaf96bc9134432bcfeab2ba8ff5904d44bc6835ec7567b'+
        '9bdbb8787162ae171a450e048ba9fec95fd0e5b8e53c54f88169ae947fc363f985705'+
        'bcd4c9bd9cf03781a4b91699821f5afbddd4e73e1d3f8f18bf0d1e1c041e41d370b5b'+
        'c32d2ab2a30be0f3153c2492b74bacd18276ce73deb89256876c07b68d49fe0d4e853'+
        '40fb6f4ebd7347dbaa51cd45e2648414b0d0198968aeb5375fc8b05fbf65918dc7145'+
        'a62f2508ee41199b072b3834b938e4958bb5e2f88d2d47f1be0742932bf40ad5388f7'+
        '5e4773708b3368a88b6107ae829ba05d44a7b6a734e402183eb15a67ec2ae78966cea'+
        '1f91550ecd296f7e94164a736283f7542120a5bd20caca515bf29c65612310656d64e'+
        'e758ae677760cc49ba299d903e7db692258aaec0341b39e0734857482a54921e2468b'+
        '67e4bb82ad2dd492606335c696e4d82909648c79583ea2732af44cf1f87a16d03fa69'+
        '55c47a0cdc37c77a91e76edbe64db95211a3945df4d4b49d017ae0d5f93bf8c39f0aa'+
        '15b87bb35107d7c29c975748adaf563e86bea16b059686d7d1f82aa0bd3e3665ddc35'+
        '237b9682bc62978fd02ede1fd5bb1d605e2fbde92bbf942bbb1da8a7ff3e74e2b5ae2'+
        'ecd776f219ede808f672c38ba312f38bb934ca6e88228870d6f0a9831558c7270f412'+
        '4bec55e595915d2e80e2939bbe8f4e588b1beb8af3a14dff54a16999b64bdd23b0821'+
        'f996bc04ac05033f9961f9275939b0f668e8eaa98594a1703320e09bb7d9c0c9b5cf4'+
        'd42eb86c37bfd949512f3c6a97e45296a1285a3ed44e0890a01a25e74280ccc998fc6'+
        'f31b9620b06e4f42600baf9f6d76b4369ab89de819a88e4eeba62319b129065b8e9eb'+
        '58d7d2f4322df00e79e523486cf1c771e6a76fbef6147afae112427db7d95574ccbe3'+
        'e4f79881488b90f3c6eee20cfa83ef3a4403f3c3438bed515921b3d335f68ff006e91'+
        '12ed06bc3568bc5fedf274d7928b3bd74c275d8296eca4bdf6a5f3d361d5c852d9a56'+
        'c282b97ffa9e49824eb8fff9812c3677830be95332b6929f5795ef39c4448966de4de'+
        'b34935187caeca6f990ccc033e2cc277b4cecfd88cb0cbcab6ef545d2d0317f0443e6'+
        'db79c8fd26ee5c2ab696045b6be7a670c2d84c5e4a5a1aecb3fa387a8cf2b1b74e2b5'+
        '6c9a66e8267c5543d05f48558dde73f0838c13921040c9cb2a5b7d6a0b10de321f9bf'+
        '2632e83b375d92a78b4e93a2d3587cb031538bbb1e796381040105e0bd2a1935fa7fb'+
        '90caf871a6b3726f13f0b02e5975a8053227a6002ab5d0f6e0554656764398bb3213b'+
        'dc2abf294fefb9183415bbc77901fa55cf74bb2616a40c6f842cd2ad80105a043f50e'+
        '795c09e484aae9225899948413bf3b1c248407e76dcda54605cd98524c9f8a9abc30f'+
        '2d94954724286752620aebe485535488175fe407ab2d9015c7aaf72a4b144d0b1b13e'+
        'e21518ee599ea942c0813e4d3819fb8d2abd8dab512ca8e8c983327f463e6cf6c4ad2'+
        '73ce3c34e18e61bb12d99f677e141d8251a3e0999df5024a7ea140f19a9db30da4be6'+
        'aefdf582aad282d006708dfff5046cbfb85ea78e548e')
TEST_KEYFILE2 = ('4DB846556770584B291EFCAD46304945'+
                 'E19F0374877BC093A943A17BAD2CFBD6')

class TestKeePass(unittest.TestCase):
    def test_keepass_wrong_password(self):
        self.assertRaises(pol.importers.keepass.BadPasswordError,
                          pol.importers.keepass.load,
                          StringIO.StringIO(TEST_DB1), 'wrong password')
    def test_keepass_load1(self):
        self.assertEqual(pol.importers.keepass.load(
                                StringIO.StringIO(TEST_DB1),
                                'test'),
            ({3605631804: {'creation-time': datetime(2999, 12, 28, 23, 59, 59),
                           'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
                           'flags': 0,
                           'id': 3605631804,
                           'image-id': 0,
                           'last-access-time': datetime(2999, 12, 28, 23, 59, 59),
                           'last-modification-time': datetime(2999, 12, 28, 23, 59, 59),
                           'level': 0,
                           'name': u'Group'}},
             [{'binary-data': '',
               'binary-description': u'',
               'creation-time': datetime(2013, 4, 19, 21, 32, 2),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 3605631804,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 21, 32, 25),
               'last-modification-time': datetime(2013, 4, 19, 21, 32, 25),
               'notes': u'comment',
               'password': u'secret',
               'title': u'title',
               'url': u'url',
               'username': u'username',
               'uuid': UUID('b29b7151-0078-0bea-85ba-fffcc924b9e3')},
              {'binary-data': '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
               'binary-description': u'bin-stream',
               'creation-time': datetime(2013, 4, 19, 21, 32, 48),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 3605631804,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 21, 32, 48),
               'last-modification-time': datetime(2013, 4, 19, 21, 32, 48),
               'notes': u'KPX_CUSTOM_ICONS_4',
               'password': u'',
               'title': u'Meta-Info',
               'url': u'$',
               'username': u'SYSTEM',
               'uuid': UUID('00000000-0000-0000-0000-000000000000')},
              {'binary-data': '\x01\x00\x00\x00<\x93\xe9\xd6\x00',
               'binary-description': u'bin-stream',
               'creation-time': datetime(2013, 4, 19, 21, 32, 48),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 3605631804,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 21, 32, 48),
               'last-modification-time': datetime(2013, 4, 19, 21, 32, 48),
               'notes': u'KPX_GROUP_TREE_STATE',
               'password': u'',
               'title': u'Meta-Info',
               'url': u'$',
               'username': u'SYSTEM',
               'uuid': UUID('00000000-0000-0000-0000-000000000000')}]))
    def test_keepass_load1(self):
        self.assertEqual(pol.importers.keepass.load(
                                StringIO.StringIO(TEST_DB2),
                                'test', StringIO.StringIO(TEST_KEYFILE2)),
            ({489459835: {'creation-time': datetime(2999, 12, 28, 23, 59, 59),
                          'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
                          'flags': 0,
                          'id': 489459835,
                          'image-id': 0,
                          'last-access-time': datetime(2999, 12, 28, 23, 59, 59),
                          'last-modification-time': datetime(2999, 12, 28, 23, 59, 59),
                          'level': 0,
                          'name': u'Group 2'},
              2437480029: {'creation-time': datetime(2999, 12, 28, 23, 59, 59),
                           'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
                           'flags': 0,
                           'id': 2437480029,
                           'image-id': 0,
                           'last-access-time': datetime(2999, 12, 28, 23, 59, 59),
                           'last-modification-time': datetime(2999, 12, 28, 23, 59, 59),
                           'level': 0,
                           'name': u'Group 1'},
              2922083484: {'creation-time': datetime(2999, 12, 28, 23, 59, 59),
                           'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
                           'flags': 0,
                           'id': 2922083484,
                           'image-id': 0,
                           'last-access-time': datetime(2999, 12, 28, 23, 59, 59),
                           'last-modification-time': datetime(2999, 12, 28, 23, 59, 59),
                           'level': 1,
                           'name': u'Group 1.1'}},
             [{'binary-data': '',
               'binary-description': u'',
               'creation-time': datetime(2013, 4, 19, 20, 39, 18),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 489459835,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 39, 34),
               'last-modification-time': datetime(2013, 4, 19, 20, 39, 34),
               'notes': u'comment 5',
               'password': u'j:4O_nuR;Q-drfx\\9cddd(N;h=NpCVO<',
               'title': u'passphrase 5',
               'url': u'url 5',
               'username': u'username 5',
               'uuid': UUID('568f7151-3c51-498f-2417-c8bb802f97a1')},
              {'binary-data': '',
               'binary-description': u'',
               'creation-time': datetime(2013, 4, 19, 20, 39, 37),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 489459835,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 39, 50),
               'last-modification-time': datetime(2013, 4, 19, 20, 39, 50),
               'notes': u'comment 6',
               'password': u'#4XOkEEcH7-C%ON.YzI<8`9V_8"]Py:N',
               'title': u'passphrase 6',
               'url': u'url 6',
               'username': u'username 6',
               'uuid': UUID('698f7151-cdc7-3271-7da8-025a3f253fd4')},
              {'binary-data': '',
               'binary-description': u'',
               'creation-time': datetime(2013, 4, 19, 20, 38, 55),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 2922083484,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 39, 12),
               'last-modification-time': datetime(2013, 4, 19, 20, 39, 12),
               'notes': u'comment 4',
               'password': u'"fw6,Ll!TcCH3N&+_H>har5--Ja(f17!',
               'title': u'passphrase 4',
               'url': u'url 4',
               'username': u'username 4',
               'uuid': UUID('3f8f7151-ea1e-3f4b-5814-4ad9f6b533e7')},
              {'binary-data': '',
               'binary-description': u'',
               'creation-time': datetime(2013, 4, 19, 20, 38, 22),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 2437480029,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 38, 38),
               'last-modification-time': datetime(2013, 4, 19, 20, 38, 38),
               'notes': u'comment 2',
               'password': u"{wt_Xv'inhmSRlCpi-t}%)s}bt=8x:?^",
               'title': u'passphrase 2',
               'url': u'url 2',
               'username': u'username 2',
               'uuid': UUID('1e8f7151-cf05-ea7b-6bcd-be2bb591d496')},
              {'binary-data': '',
               'binary-description': u'',
               'creation-time': datetime(2013, 4, 19, 20, 37, 39),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 2437480029,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 38, 14),
               'last-modification-time': datetime(2013, 4, 19, 20, 38, 14),
               'notes': u'comment 1',
               'password': u"3d,,~{66JWKw'-3_yx'-cE>'h70hO%bO",
               'title': u'passphrase 1',
               'url': u'url 1',
               'username': u'username 1',
               'uuid': UUID('f38e7151-a29d-81ae-415e-e8f3e39a9592')},
              {'binary-data': '',
               'binary-description': u'',
               'creation-time': datetime(2013, 4, 19, 20, 38, 41),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 2922083484,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 38, 53),
               'last-modification-time': datetime(2013, 4, 19, 20, 38, 53),
               'notes': u'comment 3',
               'password': u"Mx\\_L]}>,B_:$2u3}(XqQ'IT^P-n8~%Q",
               'title': u'passphrase 3',
               'url': u'url 3',
               'username': u'username 3',
               'uuid': UUID('318f7151-42be-0221-dde5-343e7ed49742')},
              {'binary-data': '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
               'binary-description': u'bin-stream',
               'creation-time': datetime(2013, 4, 19, 20, 40, 5),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 2437480029,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 40, 5),
               'last-modification-time': datetime(2013, 4, 19, 20, 40, 5),
               'notes': u'KPX_CUSTOM_ICONS_4',
               'password': u'',
               'title': u'Meta-Info',
               'url': u'$',
               'username': u'SYSTEM',
               'uuid': UUID('00000000-0000-0000-0000-000000000000')},
              {'binary-data': '\x03\x00\x00\x00]\xfeH\x91\x01{\x90,\x1d\x00\x9ct+\xae\x00',
               'binary-description': u'bin-stream',
               'creation-time': datetime(2013, 4, 19, 20, 40, 5),
               'expiration-time': datetime(2999, 12, 28, 23, 59, 59),
               'group': 2437480029,
               'image-id': 0,
               'last-access-time': datetime(2013, 4, 19, 20, 40, 5),
               'last-modification-time': datetime(2013, 4, 19, 20, 40, 5),
               'notes': u'KPX_GROUP_TREE_STATE',
               'password': u'',
               'title': u'Meta-Info',
               'url': u'$',
               'username': u'SYSTEM',
               'uuid': UUID('00000000-0000-0000-0000-000000000000')}]))

if __name__ == '__main__':
    unittest.main()

