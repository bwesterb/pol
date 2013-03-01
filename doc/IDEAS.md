
Usage
=====

Normal usage
------------

### Initialize a safe

    $ pol init -f ~/path/to/my.pol -n 2
    Generating El-Gamal group parameters, this can take several minutes ... ok!
    
    Please enter the master password for the first container:
    Enter a list-password for the first container [ no list-password ]:
    Enter an append-password for the first container [ no append-password ]:

    Please enter the master password for the second container:
    Enter a list-password for the second container [ no list-password ]:
    Enter an append-password for the second container [ no append-password ]:

    To which container should we add secrets, if no append-password
    is provided?  NOTE: you cannot deny the existence of the selected
    container.

       (1/2/none)  [none]:

### Generate a password

    $ pol generate github -n "my username is John Doo"
    Enter (append-)password [ default container ]:
    Copied generated password to clipboard.  Press any key to clear clipboard ...

### Copy a password to the clipboard

    $ pol copy github
    Enter password:

    Found 'github':
    
       my username is John Doo

    Copied secret to clipboard.  Press any key to clear clipboard ...

### List passwords

    $ pol list
    Enter (list-)password:
    
        github          "my username is John Doo"
        facebook
        google          "hi@gmail.com"

### Add a password from the clipboard

    $ pol paste -n "Some note on my secret"
    Enter (append-)password [ default container ]:

Exceptional occurances
----------------------

### Adding a password to a full container

    $ pol generate facebook
    Enter (append-)password [ default-container ]:

    The container is full.  Choose one of the following:

        c) Cancel: do not add anything. (default)
        e) Extent current container.  WARNING: you cannot deny the existence
           of this container to an adversary which has a copy of the safe
           before and after the extension.
        t) Transfer free space from another container.  WARNING: you cannot
           deny the existence of this container to an adversary which has
           a copy of the safe before and after the extension and access to
           the container from which transfer free space.

        ([c]/e/t):

### Adding a new container

    $ pol addcontainer
    To add a container, we need free space of one or more of the other
    containers.  WARNING: you cannot deny the existence of this new container
    to an adversary which has a copy of the safe before and after this
    operation and access to the containers from which we will take free space.

    Give password of a container to transfer free space from:
    Transfer space from another container (y/[n])

Format
======

pol safe
--------

Passwords and other secrets are stored in *containers*.  The purpose of
a *pol safe* is to hide containers.  An adversary must not be able
to detect how many containers there are even if he compromized some
of them.

Each container has a **master-password**.  This password is required
to read entries.  A container can have a separate **list-password**,
with which only the names of the entries can be listed.
Also, a container can have a separate **append-password**,
with which one can only add entries.  Thus:

   1. **append-password**:
      - Add entries
   2. **list-password**
      - List names of entries
   3. **master-password**
      - Read entries
      - Modify entries
      - List names of entries
      - Add entries

A `pol` safe is a msgpack encoded object:

    {'method': 'el-gamal',
     'group-parameters': {
            'p': ...,
            'g': ... },
     'digest': 'sha256',
     'key-derivation': {
            'method': 'scrypt',
            'N': ...,
            'r': ...,
            'p': ...,
            'salt': ... },
     'blocks': [ [c1, d1, h1], ... ] }

Each block is a triplet (c,d,h).  h is an El-Gamal public key.  (c,d) is
an El-Gamal ciphertext pair.

### Slices
Either a block is random junk or it belongs to a *slice*.
We will see that a container has one big slice and several small slices.
A slice has a key SliceAssymKey.  The nth block of a slice is encrypted
by the ElGamal private key

    Digest(n .. SliceAssymKey)

The (ElGamal)  plaintext of the first block of a slice starts with

    Digest(SliceAssymKey)

which is directly followed by

    SliceSymmKey

The remainder of the (ElGamal) plaintext of the first block, and the
(ElGamal) plaintext of the other blocks in the slice are encrypted
by the symmetric algorithm.

The symmetric plaintext of the ElGamal plaintext of a block starts
with the index of the first 

The remainder of the first block is encrypted by this SliceSymmKey.
The plaintext of the remained of the plaintext starts with the 32bit index
of the next block in the slice.  If this index is the index of the block
itself, this signifies that this is the last block.

The nth (n > 1) block of the slice is encrypted for the ElGamal private key

    Digest(n .. SliceAssymKey)

and then encrypted by the symmetric key

    SliceSymmKey



For each password of a container, there is a "access block" which
is encrypted for the El-Gamal private key

    Digest(1 .. Key-Derivation(password, salt))

The plaintext of the blocks starts with

    Digest(0 .. Key-Derivation(password, salt))

which is directly followed by a symmetric key

    AccessBlockKey

The rest of the block is encrypted by this AccessBlockKey and contains
a msgpack encoded


<!-- vim: set shiftwidth=4:tabstop=4:expandtab: -->
