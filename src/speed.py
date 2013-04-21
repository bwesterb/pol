""" Speed measurements of components of pol """

import timeit
import functools

import pol.kd
import pol.ks
import pol.elgamal
import pol.envelope
import pol.blockcipher

import Crypto.Random

def main(program):
    data = []
    kd = pol.kd.KeyDerivation.setup()
    data.append(('kd.derive (1000x)',
            timeit.repeat(functools.partial(kd.derive, ['']),
                                repeat=3, number=1000)))

    ks = pol.ks.KeyStretching.setup()
    data.append(('ks.stretch', timeit.repeat(functools.partial(ks.stretch, ''),
                                repeat=3, number=1)))

    bs = pol.blockcipher.BlockCipher.setup()
    def bs_encrypt():
        s = bs.new_stream('!'*32, '!'*16)
        s.encrypt(' '*20480)
    data.append(('blockcipher encrypt (500x 20KB)', timeit.repeat(bs_encrypt,
                                repeat=3, number=500)))

    def bs_decrypt():
        s = bs.new_stream('!'*32, '!'*16)
        s.decrypt(' '*20480)
    data.append(('blockcipher decrypt (500x 20KB)', timeit.repeat(bs_decrypt,
                                repeat=3, number=500)))

    randfunc = Crypto.Random.new().read
    data.append(('random (1000x 64B)',
            timeit.repeat(functools.partial(randfunc, 64),
                                repeat=3, number=1000)))

    data.append(('random (5x 1MB)',
            timeit.repeat(functools.partial(randfunc, 1024*1024),
                                repeat=3, number=5)))

    gp = pol.elgamal.precomputed_group_params()
    privkey = pol.elgamal.string_to_group(kd([], length=128))
    pubkey = pol.elgamal.pubkey_from_privkey(privkey, gp)
    c1, c2 = pol.elgamal.encrypt('!'*128, pubkey, gp, 128, randfunc)
    data.append(('EG pubkey_from_privkey (100x)',
            timeit.repeat(functools.partial(pol.elgamal.pubkey_from_privkey,
                            privkey, gp), repeat=3, number=100)))
    data.append(('EG encrypt (100x)',
            timeit.repeat(functools.partial(pol.elgamal.encrypt,
                                '!'*128, pubkey, gp, 128, randfunc),
                            repeat=3, number=100)))
    data.append(('EG decrypt (100x)',
            timeit.repeat(functools.partial(pol.elgamal.decrypt,
                                c1, c2, privkey, gp, 128),
                            repeat=3, number=100)))

    data.append(('string_to_number (10000x)',
            timeit.repeat(functools.partial(pol.serialization.string_to_number,
                            '!'*128), repeat=3, number=10000)))

    number = pol.serialization.string_to_number('!'*128)
    data.append(('number_to_string (10000x)',
            timeit.repeat(functools.partial(pol.serialization.number_to_string,
                            number), repeat=3, number=10000)))

    data.append(('_find_safe_prime',
            timeit.repeat(functools.partial(pol.elgamal._find_safe_prime,
                            1025, randfunc), repeat=3, number=1)))

    envelope = pol.envelope.Envelope.setup()
    data.append(('envelope gen. keypair (50x)',
            timeit.repeat(envelope.generate_keypair,
                            repeat=3, number=50)))
    pubkey, privkey = envelope.generate_keypair()
    msg = envelope.seal('!', pubkey)
    data.append(('envelope seal (50x)',
            timeit.repeat(functools.partial(envelope.seal, '!'*128, pubkey), 
                            repeat=3, number=50)))
    data.append(('envelope open (50x)',
            timeit.repeat(functools.partial(envelope.open, msg, privkey), 
                            repeat=3, number=50)))



    for desc, res in data:
        print '%-40s %.4f %.4f %.4f' % (desc, res[0], res[1], res[2])



if __name__ == '__main__':
    main(None)
