""" Extensions to pycrypto's implementation of ElGamal. """

import math
import time
import logging
import binascii
import threading
import itertools
import collections
import multiprocessing

# pycrypto
import Crypto.Util.number as number
import Crypto.Random

# gmpy
import gmpy

import pol.parallel
import pol.progressbar

group_parameters = collections.namedtuple('group_parameters', ('p', 'g'))

l = logging.getLogger(__name__)

# TODO add more explanation
twin_primes_constant = 0.66016181584686961514307768084108829498291015625
asymptotic_safe_prime_density = 2 * twin_primes_constant / math.log(2)

# For debugging it is convenient to use precomputed group parameters.
PRECOMPUTED_GROUP_PARAMS = {
        1024: [
            '3b92900d4eab8b5e92b0516ab02ff5bee83bf0383b36121ff3b1da8a6e492519e'+
            'e4d4f1218f9ad322532f4366c3a5c86769d8c261155442f70f89dd1098f2d7f35'+
            '0e1fc68d7086cdb884d5bf7c4e1bdb1cf314343acf4032c9c4672b18b138bffe9'+
            'cc48f67052d0ec29b41a0a88aa287f9ca84906a7bdff2ace9c008936460a700',
            '74bc65768695b1fa536adc17dd9b6190b1c6411280543757dd05ec95e15e33ced'+
            '730e4f64cd182cb3fdc7d3c49db3fafdc2353dc67cf7ad90be0ba24e2ca3b6b40'+
            'eeab88f804eb345cf0173020ee1c722405f31840d9afbaed9e65102bcfead00f3'+
            '6479012635b1666d05a1b9beb4becc90d7a82dfd1e97807b7ed1d91d78929'],
        2048: [
            'aba1287059699f87089840bea5d1d88fbfd2c919f3c88f30a90aadd1cd3f27c55'+
            'c6abc7a8cb1bf73f6c06ce8ab1e0c1b26ac8dc98fcf22714d079ad7c92a01925f'+
            'abdce2f7a5a9298fc4ea27b247eb2ab63fa1dcbd23a12824c083bdb099e54bd0d'+
            '0c18171c84fbd435d192b5a756aa1a3622109da1c24a438c15fc622b08b16b7e2'+
            '99911fa5f5ac13255c41337f5098d722c8c48bccbf711ecf08f34c4161831ae01'+
            'f739a5755cee28f0bcd424cd603c9ed14d13bf3b2b3b12aa4a34d97404ea4bd68'+
            '99efb51cf95f3753ff98f9776cd75feb2516d1679aa512791c554c81ff19837b7'+
            'ddadddca411103ee8fab3bb54079011f024f71279b5708b3072a25e8700',
            '1aba2712ef86a010533977821c0156e13db37c770aa173d3c3052d258d1e0e0f6'+
            'be483515a68df10be550054b11da2ae3c0295938d2362eefd75ec050ba2aaae2d'+
            '248bf47f5e17cdf3094e50a7b10171744453391b06e3c355d4000f8f5178bca6b'+
            'ec94fc186fa03407fbb5f3c500960d00b57b1924b0355cc8f0ae386377ec1fe35'+
            '20ce3d23810ce4323ab90ce0cbeeff23ea317c62e75af3cda1d4b791f7c53ad57'+
            '4e7b8079427420b70b2fea107379e6c4b0012d2641a8edecb6306d63aecb5eb82'+
            'b993de1b003d4849e5f1a6b91de9a86a16e019b984fe8553cf6429a60a52351e5'+
            '5915c389ffc25c4979c3da26597882d51d5298b6ae981947c8f58f763'],
        4096: [
            '6be4b2e0fab664d40c50723b0be39457e9944a840db16fc53581baaeb8115b158'+
            'ccaf8afe17af8790cfd60ea4fcf18ec67e99c0190d6f0d245088aafd478da2a81'+
            '746d65ad85e1d2705264b70d34a3ae5fb6eb95c2e24d72571fd8b16ce69fa9cb3'+
            '215b3db24734378753adbb6528458b2f3032ac75a411e3ef5d0e5e5bf566c30c8'+
            '5dd493262838389149bfff3259698a6d9669facc0cb758f77aa01c5936f87f983'+
            'b29d6266e53d18dd78de0f837f9b19d4b4261129a8ed3dd03cb0e94d7274721bd'+
            'fb3279ac932217828e81cf5338a88071856b312b72837fdd038b8a6c9448f108d'+
            'c3b56990c11f73c83fddc5ac15b7690c31df52ad6aec1d8bb9b4790b94e2ac39e'+
            'e9a14c8574b7ea9b59570310c0e317e5a880ca76a5713e2bd6bfa2328e1e53bdd'+
            '10641371af29874d65fe454f4f898dee7d45bc92026defd6f3f6b410414ebe2ff'+
            'd443bce49232ef7854896ab9101e12c4b1e6e489902a71d46b38c21046006a27c'+
            '403fc42e94e8013c5f870ed754a41b551931e06f37419a32a77cc212704bc5275'+
            'cfff75e96ce7dbc6cca393dfc9f1c61960fa3dfef72f08c65c168fe26d15f27a4'+
            '09d022e5826ae43e304619f90c877c681ce112721d1ae2a4d500b836f5f6f48e0'+
            '3069fa0befb16c954607fa51a64cee9fcfd514e9bb8796eea07e8072f6d5c6261'+
            '1e4a171e771a65bb6750341ac57bca94bc03d59551300e2c700',
            '5ed321df3170e44183ee8fd0bfe1232df2e9789e1d70efdada601319f5dc55eaa'+
            '4605217bbcd65755b9c286cf2565df278ef1d21fdc57a135354549bebb7880614'+
            '01faf70d801b46f15b1bb490c2c2324c1acecf3c3e12ee5098b3c503cb08e9b54'+
            '0dc08a7abb2ca23414d3b3e486db7f6750a5e22cabc29954920a9fa2fc1c60038'+
            '935b3a47ab13caf4c50e823479aac1d063554a8377e88d052427fcb1d013c6027'+
            'f57ca0f30f8830ec74d0d39a8d2f9705fd87184effca1562ae0e29d452633a27a'+
            '4babe97770b470005509b4c7c97afafe8985ba71ecd79c50998fb1fce8123437d'+
            '216f39fbe564304ff3c3da75c90d34a79dc3f6717662f68efd950c4dbf212091a'+
            'bfbbbc64f032af6a92a38a1939db1b020a5792528badbe3fe427b33e3a4278f6f'+
            '78c283358006a6129188740711cf1e6fc23a49173e74c2674e9c25f24a4a691a0'+
            'cf4661ea584ee6b4517675b9efa9baad933fbddc9312d62742f4587c1b8d666fc'+
            'e42701c9a2ab6bb7caaeef10ea18dfc2b214df40808f4d256fb2e3237a23fcee3'+
            '3ee8587aa0e0137aab5ce4640850815aeea63b70753543353a3de0f8ae12e9d8e'+
            '78bffcc072cf6478522ce3d0edc30a09ddd6c7fe67c88e4cc7d9164889465bf94'+
            'ba9df1e1bb1c6310f195c6aa11a2b38df817ab748116de709fb9c6c31e86d24df'+
            'ff2352ba5fad788fe70a86ce92a26d2abdbfce74dced8fdb000'],
        8192: [
            'b36de525fcac8b0bf74846f02a78194e0d557f522d13cc2d517252521e11f9061'+
            '7e45e4e049803c8d359a51692929eeef41701021f04b0a1d335db16b9c176a078'+
            'f02739dee0f1cfd317681c183072da7a2799bc265ba2affa66b9d32aa82a7677d'+
            '5da1002f6043739ff2296c5ea20ecc72f10f8ad4453f9e0b736111c4445117ba9'+
            '78120f3f62928bde22111f7fbad968caead78bf3a4ce627aadf417112fbe6c436'+
            '5e9d9f7137ee775a9b57358e16c374967a2fb8cc89c1c5e786d844328f8ee3f43'+
            'a126461a6f9445cbf3849f5c995d7d515946bad805df4a826e6628ceeb35af23c'+
            '095c1d00d41fcd9c20b52d9f7d09dd671f16fa0d3817deffdf5614ca5293b1f0c'+
            '5578a455ed7cdaa4c8344f7423e6cc5849ca086de2dfa39f52fc498f2315c5f47'+
            '4da2374b822552e976971096ac465d5c2d6e305389d834b4b50b4835c4e336168'+
            'a17c2bee6ceda9946276acb46851ae27dca40bf37b181a62eb85b49e37ef0ddad'+
            '394cfb545c3b7890f1490f0882bb5720f9d10f8e18f3d41bd237e1d1adc7d18c5'+
            '60fcf40a4ba5ec7ebead2adce13a65b39c7740a61ea38781c11d4edfdf2e74c30'+
            '56bdb0c4171dbb11d8d0da18070090a69292ca0c9a77894c3467eaba1d58d86dd'+
            'e5c3b186f7ed516ebfcf5147b6188e9e69d5573ffca5c7c81cd80afb1fafc4a1d'+
            '726c96358a1f2bbb543f65331fd7bf398aa9b77768d353263d15aaa63dd9defa6'+
            '43569f7ed43d795e4fc5f2152b36f5804a27a6d0fed38cb44185c4d16893c4bbf'+
            '75fb73f47d0eea1c770604e2453ccd6ef109796ad0cb0a3393f22b25eb9b07651'+
            'cb8028be79d68f74771eb71c06649f66fd30ac92dc83f620e6574fa03101e37ce'+
            '98d486dbe8c26130d1bf951ad23ba6796a488199a353a570fb3c06e8323f3bc8f'+
            'eea8461d9f4aed6923db78e8b6f0b629c045e50d4eae4559bf228da15f1a9c0f2'+
            '01c78dd2960f38eb29309995c7fa7431b787d65e1cdb301425b620b75fbd6ff67'+
            '493d021a252c2c82ba90d4c6c9fb54b07dc8a506603490e946a8ed36d2a043968'+
            '5d9b4beac532a6f367725fed4cb134dc209629f782a2cbe5bb3e86f0f39f3af9e'+
            '61b6f47834feb99bb5ea55438e369747d721c7b7fb9b3e22b4f2fac0b18f1fcfa'+
            'e022ed93378635004cde57b91c07f51c5a4e31a0d89db90f4752181a9aa3350c5'+
            '5353671ad05c90f256cc8c8ac9a8e5c6f8ca6877d9ddfced60c3f9cabb7c74fee'+
            '59b347197184ef1d0b0371e6dede4ec67a53c2b8777e6f811986e1334d2defaca'+
            'e6d0b85d72c499003c32460adc37c76f494bd5bc22cf741670b03326422e698ba'+
            '72555445b472aedcf4ae4c58c3fb6b396e119f26a8c4f31c1acf150e5e5680c1e'+
            '966f6ed6711ac66fa672ff0d391732fadba0c5c17e2a873492c5006b34001c084'+
            '41b2994ccaf240879780f61e6f02acdda00',
            'f68905a8ce5a66a928b844d8ceee74260afd1bca2684f18aec8eb231a59a7f22a'+
            '61e5343f90b7e2c209a496ab7a4c291ca6410e1b2a1276a837a6d8c9a1dffcd7a'+
            'b66b9b2b58d43115b1f08ddbfba37d10fb7e42ee90eb64d654625051062cb2e80'+
            '7780e984a37ba2decf06b8ed7e8ba9097fbd04b66f0990e661299789fc6fbaf9e'+
            'e74be122a466b2ebc586b4461e40d94b470eeb0e2e4a4b5bd6f2bba16d54f0b98'+
            'b107e298827b1c83ebd18e03cbf6d96a1982d10a10d0c0f3e2c91d2881e1abdad'+
            'cd6033a8becaa21eb76acd499e58a716fdd813a6d476d7ddd8caf24b0ebc1a610'+
            '43cba1ac3464de894007b8634343077dc7f271843f7fc11ae02baabd96abfc900'+
            'c9b773f221e55b695985891962dc8496c471b7237bd2889ca1864dadbeb03f6a8'+
            '64e8ffb332eccef0938dba978f7fbfde7637952eeb9a38d1ca45fc2214d1675d2'+
            'd50d3fb9fc3948c78ce2772d789bb763b23735c97c70096bba278a40500006923'+
            'ec09c4540ac2cddd7f1e17e446f7bf97e8f4446766c7064cb65ead1f7b99a5e49'+
            'ba5ad898827b47ea9c5320019f2c10e870d21e0876e8baa6e404b5f4bd2c20b2c'+
            'acb97076b3b4ca48567c2360ba144aead0932bc7b121434c8f339d71636c09d7f'+
            '29a20b6d2c15981436c8c9333d3a50b99fc34a0beeacca5c49f826d0aaa0122bf'+
            'c8c735d251d06ddb4181a41b6d8342685118b3a1b035496f492efc511eb16de60'+
            'b26f5ebcb35c46f349a87360e2f47c26b417e0e8a027d5d45797e07d615c3829b'+
            'c86cce889698b2789e0a83b068fc1c6f6c685c8528a533fafa9d287a542493ce9'+
            'c2f427fb49cdfee8e4b2f0dbaf2c9e78f72c258e1d7976b653a9ef2d1ecaf7902'+
            '40fa5fde61e10841437ac21d898343b3a8023018f0d4752cee4611e474287d5e4'+
            'c9a91fbead8e4f754f59cfa32141431bc86cf77046cb37e54a613e36e8e47f9eb'+
            '9ece5ec44c4ed263221d6b04f6de0407d1051ac2720b7d24fb266eb49dc5a0caa'+
            'ebb638f0ed2f1c97024f523a1255066cea871d2a822397694d08429cfd4b7f80c'+
            'a0f7b5ebf4a3aad0e8c0b364855320d1c649be3b855d7bb80aff5fc49820d891a'+
            'f9e9471d79c474b8dbd7ede451d91d7b05d2f4eeb72b84a1b47a71e2f4e582681'+
            'a43eeede68d8bae88d54744a0b16f60b514f591018479565b40a0b5431d9eac07'+
            'b2a8d914afcb31897841b9eda64e7f589137e05352bfd83e1a0bf14fce8ef0faa'+
            '4ee1287e3f26a7e61bf8e125cfa243f4aea184f3419f2ded9d574151447130f66'+
            '309167bf7752c6e532a18648fd40eed11caed39ad8d8a48cdf46d9f2c4c28144d'+
            '88d323b70777b41de983446ffb12b0b23bb9c2421b8d55d16e41fbbbc1df011b5'+
            '7edac0e70f1954f2b7065e7572745e693e6980f9de3ff32e5ee6e5962e47e7c51'+
            'a66d45e6a2a6991731aea19f955d6770a']
        }

if not number._fastmath:
    l.warning("pycrypto not built with _fastmath module.  A lot will be quite "+
              "slow")

def _find_safe_prime_initializer(args, kwargs):
    Crypto.Random.atfork()
    kwargs['randfunc'] = Crypto.Random.new().read

def _find_safe_prime(bits, randfunc=None):
    """ Finds a safe prime of `bits` bits """
    r = gmpy.mpz(number.getRandomNBitInteger(bits-1, randfunc))
    q = gmpy.next_prime(r)
    p = 2*q+1
    if gmpy.is_prime(p):
        return p

def precomputed_group_params(bits=1024):
    """ Return precomputed group parameters.

        NOTE For small group parameters this is unsafe. """
    if not bits in PRECOMPUTED_GROUP_PARAMS:
        raise ValueError("No precomputed group parameters of %s bits" % bits)
    p, g = [gmpy.mpz(binascii.unhexlify(x), 256)
                for x in PRECOMPUTED_GROUP_PARAMS[bits]]
    return group_parameters(p=p, g=g)

def generate_group_params(bits=1024, nthreads=None, progress=None):
    """ Generates group parameters for ElGamal. """
    # Find a safe prime as modulus.  This will take at least several
    # seconds on a single core.  Thus: we will parallelize.
    start_time = time.time()
    if nthreads is None:
        nthreads = multiprocessing.cpu_count()
    l.debug('Searching for a %s bit safe prime p as modulus on %s threads',
                bits, nthreads)
    safe_prime_density = asymptotic_safe_prime_density / (bits - 1)
    if progress:
        progress('p', None)
        def _progress(n):
            progress('p', pol.progressbar.coin(safe_prime_density, n))
    else:
        _progress = None
    p = pol.parallel.parallel_try(_find_safe_prime, (bits,),
                            initializer=_find_safe_prime_initializer,
                            progress=_progress, nthreads=nthreads)
    # Find a safe `g` as generator.
    # Algorithm taken from Crypto.PublicKey.ElGamal.generate
    # TODO Should we use a generator of a subgroup for performance?
    if progress:
        progress('g', None)
    l.debug('Searching for a suitable generator g')
    start_time = time.time()
    q = (p - 1) / 2
    while True:
        g = gmpy.mpz(number.getRandomRange(3, p))
        if (pow(g, 2, p) == 1 or pow(g, q, p) == 1 or divmod(p-1, g)[1] == 0):
            continue
        ginv = gmpy.invert(g, p)
        if divmod(p - 1, ginv)[1] == 0:
            continue
        break
    l.debug('Found one in %.2fs', time.time() - start_time)
    return group_parameters(p=p, g=g)
