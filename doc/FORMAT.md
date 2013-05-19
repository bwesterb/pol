pol safe format
===============

This document describes the (current) format of a pol safe.

Magic bytes
-----------

Every pol safe starts with the following 18 bytes.

    70 6f 6c 0a d1 63 d4 97 7a 2c f6 81 ad 9a 6c fe 98 ab

Note that `70 6f 6c 0a` is `"pol\n"`.

Plaintext object
----------------

The remaining data is a "simple object" encoded using
[msgpack](http://msgpack.org).
This is called the *plaintext object* of the safe.
A "simple object" is very similar to [JSON](http://json.org) defined objects.
It is recursively defined as following.

A simple object is one of the following:

 * a (byte)string,
 * a 64 bit floating point,
 * a 64 bit unsigned integer,
 * a 64 bit signed integer,
 * a special value *nil* (null, None, ...),
 * a boolean,
 * a (possibly empty) list of simple objects *or*
 * an mapping of strings to simple objects.

[msgpack](http://msgpack.org) is an efficient and widely supported
binary encoding of these simple objects.

This is an example of the plaintext object of a safe (in
Python notation):

    {'block-cipher': {'bits': 256, 'type': 'aes'},
     'block-index-size': 2,
     'bytes-per-block': 128,
     'envelope': {'curve': 'secp160r1', 'type': 'seccure'},
     'group-params': ['+\xf2\x9f\xb7L\x0b\xe9\xd0M\xa8\xd6\x01\x19\x0c\x14h\x06\x0f\x8eW_6Q\xa5A6U\xa5x\x19\xd6\x15!\x8f\xc5\x9f\xec\x1d!zy\x99\x96q<\xa2\xaec"\xfeb\xce\xbd\xf6L?Xi\x1f\xe0_\xff*s\x8d\x81I*\xd9_\xafM\xb7\x8aX\xd1\x1a\xd3]#\xe3\x94O8\xc4(\xb4\x06T\xaf\x83\'\x1c\x87\x15\x0c\x0f\xf4\xd4}\x07J\x12\xbf\x03\xda\x8c\xef\xe3X\xf6\xd8\xb6O\xa6\xe5\x92\xc8\xcaS\x02u\xfa\xd9P\x0f\xc5\x97\x01',
                      '\x8aX\x98%\x9c\x01\xbc\xfbfi\xc2\xcd\xa0\xbf\x1a\x0f\x06\x04\xe1\xb9J\x8c\r>\x93R\x98\xe6\xa4\xab|\xc1\x8e4\x02\x8a\x0ej\xd0\xb1\xc8\xe5\xbb\xf3\xe3\xd0\xf7{\xd1\xd5\x88&\xdd\x94\xc0\xe89\xef*Rv\x89\x10\x9a\xb2\xf7\xb1\xf4\xa9\x04\xcf\x7f\xf9d\xa5V\x16\x11\x7f\x81\x91\xefd\x95\xe5\x17\xc1\xa9X\xf8\x0b\xb9\xc5\xed\xd2\xbf\x81#\xc5\xc4\x96`,\x93\x89\x97\xf5Ud\x97*\xc8\xab\x1b\x99Q\xdc\xebY\xf4btg\xc8\xa3\x91\x1ds\x01'],
     'key-derivation': {'bits': 256,
                        'salt': '\xab\x8a\x0b\x9fx\x07{\x19\xd8`\x81\x02\xe1\x03L\x87\x7f@\xbc:\x95\xcbR\xb3)\x9fp[\xa5_\x1aM',
                        'type': 'sha'},
     'key-stretching': {'Nexp': 15,
                        'salt': '\x14\xb96Q\xf0\x00\xd5\x87f\xacT\xa55p\x18xCj3f_9\xd8\xe4\xdf\xc8l\x93\xf5Q\xcb\x93',
                        'type': 'scrypt'},
     'n-blocks': 1024,
     'slice-size': 4,
     'type': 'elgamal',
     'blocks': [['\xadC\xa6\xdf\xc1oC 5\xd3g\xc3\xadg)\x1c7yj/\x15~x\xc8:\x7f\x89P\xcf\x11\t\x14\x0f\x14|\xe0\x11\xa6I\x82HX\x0c\x96\xc2Z\xaa\xc0$jV\x15Pi\xa1\xdc\xf3S\xa3\xf6\x0c\xcf\xb2_\xa7_\xd2\x9f\xa9\xa8\r\xa1\xf9\x01\xf3\x99OE\x84R\xd9\x0bRe\xeck\xbc\xaf\x93A\x0b\xa3\xec\x0c\x96\x1eo\xc0\xc4\x1b\xc71\xe7vy\xb9\xb1\xdeUMh\\\x8e=F\x17\xd4\xb3\xb5H\x05l/\xc1\x0b\xa7$9\x01',
             '\xbe#H\xec\x03:\r\xa3\xf6;\xee$\x8b\x14\x18\xd7z\xbf\xd3P\xcc\xfe\xc6\x8fu\xb9\xc5\xf1\xaf/\x14\xb6\x8c:vT\x88\xab\xd5\xf9\xba)1\x9b\xc1\x85\xcf\xc6\\W&YG\xc6\x90\xc9\x7f;\x91\xea\x82\x93\x8f\xda\x00\xf9\x01\x1d\xbdUF\xb2\r\x8c\xfdmf\x01\x8e$\xa5lu\x010\xe8\xb7U\x1a\xa1\xd8S]\xce\xd5\xa4\x08\xcd\xa4c\x87\x07\x7f\xf8\xc4\xd1ZI\xdd\xf5\x04\x13\xb6A\xb8X\xad\xa5\xbb.\x82\r\xa3Y\xd3\x83\xf9\xc9',
             '\xd33\x8dG\x8f\x17\xe4\xcd\xb9\x92\xa3\xa4\xa4\xe9\xc0\x19K\x9bP\xc0CD"D[M}\xeeU\xef\x99\xfb\xf3WRl\x17I\xc7\xc2\x1dM,=\xba\x16:6.\xb1\xb7\xcd\xcaw\xf1w\x0c~\xb5\xc5\xd3Zt\xf8u\xe8S\x9c(\x93\xe1\x83\x15\xd5 \x08H\x12\xcb\xf8Y\x9c\x19\xfcu\x0bk\x05c%P_\xad&f\x97\xaa\xcb\x93\x81z\xab\x9e\x18\x13\xae\xad\xe7\x94{\xa0\x1f#*\xaa\xcbc\x06\x08\x7f\xe2\xa6\xc8\x82\xd6/\xa3#\x01',
             '\xac\xa3\xcfW\xbb6\x9d1K\xcd-\x1c\xfc\x9c\t\xfe\x83\xbd\xa5\x08\x9b\xd1\xa6DO\xb5\x05W\xdd2\x945'],
             ...]}

Note that we truncated the `blocks` list.

The pol format is designed to be flexible.  It is, for instance,
easy to add support for another blockcipher than AES, the current default.
The blockcipher that is used, is specified in a mapping under the
top-level `block-cipher` attribute.  The `block-cipher` is a so-called
**primitive** of the safe.  The configurable primitives are:

  1. `block-cipher`.  The symmetric cryptography used.  The default is
     AES-256 in CTR.  See below for details.
  2. `key-stretching`.  The method to derive a key from a password.
     The default is scrypt.  Again: see below for details.
  3. `key-derivation`.  Used to derive keys from list of strings.
     The default is based on SHA-256.
  4. `envelope`.  Used to seal messages with public/private key
     cryptography.  The default is based on Elliptic Curve IES on secp160r1.

The format of the safe itself, responsible for the deniable encryption,
is also configurable.   By default it is based on El-Gamal rerandomization.

First we will give an overview of the format.  Then we will go into the
details.

Overview
--------

A pol safe can have zero or more containers.
Each container has a master password.  It can have a list-password and
an append-password.  A containers contains entries.
Each entry is a triplet: key, note and secret.

Containers are hidden in a large list of blocks.  Typically a safe
contains 1024 blocks.  Each block belongs to a container or is random junk.
We cannot distinguish a block that is random junk from a block owned
by a container.

Each block is in fact a quadruple: (`c1`, `c2`, `pk`, `m`).
The pair (`c1`, `c2`) is an El-Gamal ciphertext
for the private key corresponding to the public key `pk`.
This is true, even if the block is junk.  If the block is junk,
the plaintext and private key are randomly generated and thrown
away.  `m` is a key related to the private key of the block,
used to improve performance of finding blocks.  See the details below.

To accommodate for the different levels of access each password gives,
a container is split into (at most) five slices.
Every block that belongs to a container, belongs to one of the five slices.
There are three small *access slices*.  One for each password.
Then there is a *main slice* that contains the entries.
Finally, there is an *append slice* that contains the sealed
passwords added with the *append-only password*.

Each slice has a *slice key*.  In the case of the *master password access
slice*, this is the key-stretching primitive applied to the master-password.
In the case of the master slice, this is a randomly generated key stored
in the list-password and master-password access slices.
The El-Gamal private key of a block of a slice is derived deterministically
from the *slice key* with the key-derivation primitive.
The El-Gamal plaintext of a block is itself a ciphertext:
it is encrypted with the blockcipher primitive using another key
derived from the *slice key*.
The first few blocks of a slice, contain the indices of the other blocks of
the slice.

Thus, to open a container given a password:

 1. First derive the access slice key from the password using the
    key stretching algorithm.
 2. Find the access slice by trying to decrypt each block using the
    appropriate derived key.
 3. Decrypt the first and other blocks of the *access slice*.
 4. Using the key for the *main slice* or *append slice* stored in the
    *access slice*, derive the *slice key* and find the main/append slice
    as before.

The *master slice* contains:

 1. A private key used to decrypt entries in the *append slice*.
 2. A list of (key, note) for each entry.
 3. The ciphertext of the list of secrets.

With a *list password* one can decrypt the *master slice*, but you
need the *master password* to decrypt the ciphertext of the secrets
in the *master slice*.

The *append slice* contains:

 1. The public key used to seal entries.
 2. A list of sealed entries.

Whenever the safe has been accessed, it is rerandomized.
We will explain how rerandomization of a block is performed.
Recall that El-Gamal encryption is defined as
follows:

    E(m) = (g ** r, m * (g ** x) ** r) mod p

Where

 * `g` is a generator of the finite field **p**
 * `r` is a random element of the field
 * `x` is the private key
 * `g ** x` is the public key

Then given any such ciphertext (`c1`, `c2`)
one can consider

    (c1 * g ** s, c2 * (g ** x) ** s)

for a random `s`.  It is easy to check that is an El-Gamal ciphertext
for the same plaintext.  We just changed the random number from `r`
to `r+s`.  This is called a rerandomization of the ciphertext.  This
rerandomization is applied to each block of the safe.

See `_eg_rerandomize_block` in [safe.py](../src/safe.py).

Before we discuss the details of the format of a safe, we
look at the primitives.

Primitives
----------

### Blockcipher

Given an initialization vector and a key, the blockcipher
encrypts and decrypts messages by blocks.

The default (and the only supported configuration) is:

    {'type': 'aes', 'bits': 256}

This is AES-256 in CTR mode.  Its blocksize is 16 bytes.
See [blockcipher.py](../src/blockcipher.py).

### Key-stretching

The default (and the only supported type) is
[scrypt](http://www.tarsnap.com/scrypt.html).
The default configuration is:

    {'type': 'scrypt',
     'Nexp': 15,
     'salt': < a randomly generated 32 byte string > }

 * **Nexp** is the 2-log of the value *N* passed to scrypt.
 * **salt** is the salt passed to scrypt.

#### Example

The password `waasdasdada` stretched with the default configuration
and salt `waasdasdaa`, gives the following key in hexadecimal notation:

    69e9b3dafbc7cbe8d903fb1e6e1633da6c45fcd3f6edf66d34532a2883a7abd9390bbc834020a0539d8304570ee7b9eb64ab00ecad1bbd89e1a93c2c38646581

See [ks.py](../src/ks.py).

### Key-derivation

The key-derivation is basically a hash function from
the finite tuples of strings to strings of arbitrary length.
Although the key-derivation generates strings of arbitary length,
it specifies a natural length.

The default (and the only supported type) is based
on SHA2 (`sha`).  The default configuration is:

    {'type': 'sha',
     'bits': 256,
     'salt': < a randomly generated 32 byte strong > }

 * **bits** is the variant of SHA2 to use.  Only `256` is accepted.
 * **salt** is a salt used.

Given a list of string `[s1, ..., sn]`,
one can consider the big string

    H ( H(s1) | ... | H(sn) | H(salt) | H(s(0)) ) | H ( H(s1) | ... | H(sn) | H (salt) | H(s(1)) ) | ...

Here `H` stands for SHA-256 and  `s(i)` for the big endian 16 bit encoding of `i`.
One can trunctate this string to any length.  This is the default key-derivation.
The natural length of this key-derivation is 32 bytes.

#### Example

The 128 byte key derivation of `['a', 'b', 'c']` with salt `c` is in
hexadecimal notation

    b87a32912e780ab8e22555d132fec8c01b2867128ebb4e56dcac029e71ac902f9e6c49cc332427586fef3cd34330d2724494c09044f475b7c47c24774b996059a8fe87e36dde9c60b1e3838d5a891d023f58b73667672d3b796224e6b7c617bb6b20a9c08b49f40f9b37f5f34be841e957e415638b6cc03cb4c52906044e65e5

See [kd.py](../src/kd.py).

### Envelope

The envelope primitive has three operations.

  1. Generate a public/private keypair.
  2. Given a public key, seal a message for that key.
  3. Given a prive key and a sealed message, decrypt it.

The default type is based on [seccure](http://point-at-infinity.org/seccure/),
which in turn is based on ECIES.  The default configuration is:

    {'type': 'seccure', 'curve': 'secp160r1'}

 * **curve** is the elliptic curve used.  Any curve supported by
   [py-seccure](https://github.com/bwesterb/py-seccure) is accepted.

#### Key generation

A private key is randomly generated.  Its length depends on the
`keysize` of the curve.  A public key is derived using the same
method as the commandline util
[seccure-key](http://point-at-infinity.org/seccure/) uses.
The public and private key are represented in the binary
format as is used in seccure.

#### Sealing a message

A message is sealed compatible with the commandline util
[seccure-encrypt](http://point-at-infinity.org/seccure/).

#### Decrypting a message

A sealed message is decrypted compatible with commandline util
[seccure-decrypt](http://point-at-infinity.org/seccure/).

#### Examples

An example keypair, in hexadecimal notation, is

    004da4d9fc62d0e5f27cc2aac41272e2e94ef04f9c 5ff96fc11a09721d71a844ec2c0ea160ce0aca7ce0

The following

    00143617e9c11a7f6b58eca06e2c68b4d098ea4f5bf8fa85aab33721f06a0ed4d08bfe7d8ad22bf2ce7507904b3245121df1d88fc691093c77991b3998

is the sealed message `'This is a very secret message\n'` for
the private key `my private key`.

See [envelope.py](../src/envelope.py),
[py-seccure](https://github.com/bwesterb/py-seccure) and
[seccure](http://point-at-infinity.org/seccure/).

The safe
--------

### Serialization of big integers, block indices and more

In various places, we need to store big unsigned integers.
`msgpack` has no support for these.  We serialize a big unsigned integer
as a bytestring in little endian.  Thus the string `hello` represents
the number 478560413032.  See [serialization.py](../src/serialization.py).

Also block indices are serialized.  In the plaintext object there is an
attribute `block-index-size`.  A block index `i` is serialized
with `block-index-size` bytes in big endian.

The length of a slice is also serialized in big endian.
In the plaintext object there is an attribute `slice-size` to specify
how many bytes are used. 

### Slices

A slice consists of a list of blocks.  For instance `[43, 2, 12]`.
This slice has three blocks.  The first is the block with index 43.
The second is the block with index 2.  The last block is the block with
index 12.

Let `Ks` denote the key of the slice.

#### El-Gamal private key

The El-Gamal private key for the *i*th (starting from 0) block
of the safe is

    KD([ Ks, KD_ELGAMAL, i])

where `KD_ELGAMAL` is the string given in hexadecimal notation by

    d53d376a7db498956d7d7f5e570509d5

and KD is the key-derivation primitive.  Note that `i` is serialized
as a block index depending on `block-index-size`.

See `_privkey_for_block` in [safe.py](../src/safe.py).

#### Symmetric key

The symmetric key for the slice is

    KD([ Ks, KD_SYMM])

where `KD_SYMM` is the string given in hexadecimal notation by

    4110252b740b03c53b1c11d6373743fb

See `_cipherstream_key` in [safe.py](../src/safe.py).

#### Marker

Recall that a block is a quadruple (`c1`, `c2`, `pk`, `m`),
where (`c1`, `c2`) is an El-Gamal ciphertext encrypted with
the public key `pk` and we did not yet explain `m`.
`m` is called the marker.  If it is a block of the slice with
key `Ks` and it is the `i`th block of the safe, then `m` is

    KD([ Ks, KD_MARKER, i])

To check whether a key decrypts a block, it is faster
to check the marker, than it is to do a trail decryption
or to check `pk`.

See `_marker_for_block` in [safe.py](../src/safe.py).

#### The El-Gamal group parameters

In the plaintext object the top-level attribute `group-parameters`
is a pair (`p`, `g`), that specifies the finite field of
order `p` and generator `g` that is used for the El-Gamal
cryptography.

#### El-Gamal plaintext

The plaintext of a block is a number.  It is interpreted
as a string by using the serialization for big integers,
as defined above, and truncating to `bytes-per-block` bytes.
`bytes-per-block` is a top-level attribute of the main
object that specifies how many bytes are stored in each block.

See `group_to_string` in [elgamal.py](../src/elgamal.py).

#### The first blocks

The El-Gamal plaintext of the first block of a slice begins

    KD([ symmetric-key ], blockcipher-blocksize)

Where `symmetric-key` is the symmetric key for the slice
and `blockcipher-blocksize` is the blocksize of the block-cipher.

It is followed by

    IV

again of length `blockcipher-blocksize`.  The remainder of the plaintext
of the first block is encrypted using the block-cipher
with `symmetric-key` as key and `IV` as initialization vector.
Call this the blockcipher plaintext.

The blockcipher plaintext starts with

    number-of-blocks

which is encoded in the same way as a block index.  See above.  This
is the number of blocks in the slice.  This is followed by
`number-of-blocks - 1` indices.  These are the indices of the other
blocks of the slice.  It is quite possible the blockcipher plaintext
is too small for all the indices.  In this case the indices that
did not fit continue in the next block of the slice.  Et cetera.

After that the size of the slice is serialized.  The remainder is
the contents of the slice, which should be truncated to the specified size.

See `_load_slice_from_first_block` in [safe.py](../src/safe.py).

#### Compression of the data of a slice

The data of a slice starts with a single format byte.

 * If the format byte is 0, then the remainder is a
   [msgpack](http://msgpack.org) encoded simple object.
 * If the format byte is 1, then the remainder is a
   [msgpack](http://msgpack.org) encoded simple object compressed
   with [zlib](http://zlib.net).

See `string_to_son` in [serialization.py](../src/serialization.py).

#### Access slices

The key of an append slice for a password `pwd` is

    KS(pwd)

The data of an access slice is the quadruple

    ( magic, type, key, index )

 * **magic** is always in hexadecimal

        1a 1a 8a d7

 * **type** is either

    * 0, then this is an access slice for a master password.
    * 1, then this is an access slice for a list-only password.
    * 2, then this is an access slice for an append-only password.

 * **key** is
    
    * The full key of the container when this is a master password access slice.
    * The list key of the container when this is a list-only password
      access slice.
    * The append key of the container when this is an append-only
      password access slice.

 * **index** is

    * The index of the main slice when this is a master or list-only password
      access slice.
    * The index of the append slice when this is the append-only password access
      slice.

#### Key derivation

The list key `Klist` of a container is derivable from the full key `Kfull`
of a container.  Also, the append key `Kappend` is derivable from the
list key `Klist`.  This is done as follows.

    Klist     = KD([ Kfull, KD_LIST ])
    Kappend   = KD([ Klist, KD_APPEND ])
    KD_LIST   = d5 3d 37 6a 7d b4 98 95 6d 7d 7f 5e 57 05 09 d5
    KD_APPEND = 76 00 1c 34 4c bd 9e 73 a6 b5 bd 48 b6 72 66 d9

#### Append slices

The key of an append slice is the append key of the container it belongs to.
The data of an append slice is the triple

    ( magic, pubkey, entries )

 * **magic** is always in hexadecimal

        2d 50 39 ba

 * **pubkey** is the public key from the envelope primitive with which the
   entries are sealed.

 * **entries** is this list of sealed entries.  An entry is a triple

        ( key, note, secret )

that is serialized in the same way as the data of a slice.  See above.

#### Main slices

The key of a main slice is the list key of the container it belongs to.
The data of a main slice is the quintuple

    ( magic, append_index, entries, iv, secrets )

* **magic** is always in hexadecimal
  
        33 65 3e fc
  
* **append_index** is the index of the first block of the append slice of
  the container.
  
* **entries** is a list of pairs (`key`, `note`).
  
* **iv** is the initialization vector with which `secrets` is encrypted.
  
* **secrets** is the list of secrets, encoded in the same way as the data of
  an access slice, encrypted with the full key and initialization vector `iv`.
