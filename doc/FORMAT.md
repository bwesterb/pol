pol safe format
===============

Magic bytes
-----------

Every pol safe starts with the following 18 bytes.

    70 6f 6c 0a d1 63 d4 97 7a 2c f6 81 ad 9a 6c fe 98 ab

Note that `70 6f 6c 0a` is `pol\n`.

Plaintext data
--------------

The remaining data is "simple object" encoded using
[msgpack](http://msgpack.org).
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

Before we explain the main simple object, lets look at an example:

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
     'type': 'elgamal'}

