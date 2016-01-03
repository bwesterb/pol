pol
===

**WARNING** pol is a young project, there might be errors, even
vulnerabilities --- please help out by testing or reviewing its code.

pol /pɵl/ is a password manager with two important features:

1. A nice commandline interface. Want to generate a password? Just type:

   ::

       $ pol generate github "my username is John Doo"
       Enter (append-)password: 
       Copied password to clipboard.  Press any key to clear ...

   This will generate a new password; copy it to the clipboard and store
   it under the key *github* with the note *my username is John Doo*.

   Want to retrieve the password you just stored? Just type:

   ::

       $ pol copy github
       Enter password: 
        note: 'my username is John Doo'
       Copied secret to clipboard.  Press any key to clear ...

   See below for a description of all commands.

2. Hidden containers. The best way to keep a secret, is being able to
   deny you are keeping one. Sometimes you are forced to give up your
   passwords. For instance, by a criminal, government or employer.
   Luckily a pol safe can have multiple containers. Each container is
   opened by its own passwords. If someone does not have a password of a
   container, he cannot prove the existence of the container in any way.
   Even if he has multiple versions of your safe! Thus if you are forced
   to open your pol safe, you can give a password to an uninteresting
   container and keep your real secrets safe.

Getting started
---------------

Installation
~~~~~~~~~~~~

First, we install pol.

On Debian Wheezy
^^^^^^^^^^^^^^^^

::

    $ sudo apt-get install libgmp3-dev build-essential \
                            python-dev python-pip
    $ sudo pip install pol

On Ubuntu 13.04 and 14.04.1
^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    $ sudo apt-get install libgmp-dev build-essential python-dev \
                        python-pip libssl-dev libyaml-dev libssl-dev
    $ sudo pip install pol

On Mac with homebrew
^^^^^^^^^^^^^^^^^^^^

::

    $ brew install python gmp
    $ pip install pol

On Mac with MacPorts
^^^^^^^^^^^^^^^^^^^^

Install `MacPorts`_. Then run

::

    $ sudo port install gmp py-pip py27-crypto
    $ sudo pip-2.7 install pol

If you get ``pol: command not found`` when you try to run ``pol``, add
``/opt/local/Library/Frameworks/Python.framework/Versions/2.7/bin`` to
your ``PATH``. For instance, like this:

::

    $ echo 'export PATH=/opt/local/Library/Frameworks/Python.framework/Versions/2.7/bin:$PATH' >> ~/.profile

Creating a safe
~~~~~~~~~~~~~~~

Then, we create a new safe with ``pol init``. ``pol`` will ask you for
the passwords of your containers.

::

    $ pol init
    You are about to create a new safe.  A safe can have up to six
    separate containers to store your secrets.  A container is
    accessed by one of its passwords.  Without one of its passwords,
    you cannot prove the existence of a container.

    Container #1
      Each container must have a master-password.  This password gives
      full access to the container.

        Enter master-password: 

      A container can have a list-password.  With this password you can
      list and add entries.  You cannot see the secrets of the existing
      entries.  Leave blank if you do not want a list-password.

        Enter list-password [no list-password]: 

      A container can have an append-password.  With this password you
      can only add entries.  You cannot see the existing entries.
      Leave blank if you do not want an append-password.

        Enter append-password [no append-password]: 

    Container #2
      Now enter the passwords for the second container.
      Leave blank if you do not want a second container.

        Enter master-password [stop]: 
        Enter list-password [no list-password]: 
        Enter append-password [no append-password]: 

    Container #3
        Enter master-password [stop]: 

    Generating group parameters for this safe. This can take a while ...
    [#####################=========================================================]
      449 tried,  63.6/s  56.7%                     0:00:18
      allocating container #1 ...
      allocating container #2 ...
      trashing freespace ...

Common commands
---------------

generate a new password
~~~~~~~~~~~~~~~~~~~~~~~

This will generate a new password, copy it to your clipboard and store
it under the key ``facebook``.

::

    $ pol generate facebook
    Enter (append-)password: 
    Copied password to clipboard.  Press any key to clear ...

You might want to add a note. This note is shown when you retrieve the
password.

::

    $ pol generate facebook "e-mail: john@doo.org"
    Enter (append-)password: 
    Copied password to clipboard.  Press any key to clear ...

If you just want a password, but do not want to store it, omit the key:

::

    $ pol generate
    Copied password to clipboard.  Press any key to clear ...

If you want to write it to the screen, add ``--stdout``:

::

    $ pol generate --stdout
    $^NxY{&Fsy,&->Gi$RZ}

There are several options to change the style of the password:

::

    # xkcd style password with 40 bits of entropy
    $ pol generate --stdout --kind english --entropy 40
    dirty papal nephew repair

    # alphanumeric password that would take ages to bruteforce with 10 tries per second
    $ pol generate --sdtout --kind alphanum --web-crack-time ages
    NNrZ9g8Sy

For all options, see ``pol generate -h``.

Copy password to clipboard
~~~~~~~~~~~~~~~~~~~~~~~~~~

To copy a password stored under the key ``digid`` from the safe to your
clipboard, write

::

    $ pol copy digid
    Enter password: 
     note: 'used the e-mail john@doo.org'
    Copied secret to clipboard.  Press any key to clear ... 

List passwords
~~~~~~~~~~~~~~

To list the entries in a container, use

::

    $ pol list
    Enter (list-)password: 
    Container @280
     github               'user: johndoo'
     router             
     facebook             'email: john@doo.org'
     bios.notebook
     bios.pc

You can filter results as follows

::

    $ pol list bios
    Container @280
     bios.notebook
     bios.pc

Edit entries
~~~~~~~~~~~~

To edit all entries in a container, use

::

    $ pol edit
    Enter password:

This will open up your default text editor (``$EDITOR``) with, in this
example:

::

    github        #1 user: johndoo
    router        #2
    facebook      #3 email: john@doo.org
    bios.notebook #4
    bios.pc       #5

Simply edit the entries, save the file and exit the editor. ``pol`` will
apply the changes. Remove lines to remove entries; reorder lines to
reorder entries and add a line to add an entry.

By default, the secrets are replaced by pointers like ``#2``. To change
a secret, simply replace the pointer by the secret. For instance:

::

    github        mypassword user: johndoo

To show the secrets by default, use ``pol edit -s``.

You can filter the entries to edit: executing ``pol edit bios`` will
present the following file to edit.

::

    bios.notebook #1
    bios.pc       #2

With ``pol edit -m`` you can enter multiple passwords to edit entries of
multiple containers. Enter as many passwords as you like and leave the
prompt blank to continue to the editor:

::

    $ pol edit -m
    Enter password: 
    Enter next password [done]: 
    Enter next password [done]: 

You will be presented a file like:

::

    CONTAINER 1
    github        #1 user: johndoo
    router        #2
    facebook      #3 email: john@doo.org
    bios.notebook #4
    bios.pc       #5

    CONTAINER 2
    supersecret   #6
    recoverykey   #7

Move entries under different headers to move them between containers. It
is that simple.

Technical background
--------------------

For those who like context-free mumbo-jumbo: pol uses *El Gamal
rerandomization*, *scrypt*, *AES-256 CTR*, *ECIES* on *secp160r1*,
*SHA-256*, *Fortuna* and *msgpack*. For actual details, see
`FORMAT.md`_

Attribution
-----------

The developers of pol are

-  Bas Westerbaan

Others have been involved indirectly:

-  Bart Jacobs suggested using El-Gamal rerandomization
-  Wieb Bosma and Eric Cator have helped approximating the density of
   the safe primes.

``pol`` builds on dozens of other (open source) projects, notably:

- `pycrypto`_
- `gmpy`_
- `seccure`_
- `zxcvbn`_

Finally, the following projects have influenced the design.

-  `Password Safe`_


.. _Password Safe: http://passwordsafe.sourceforge.net/quickstart.shtml
.. _pycrypto: https://www.dlitz.net/software/pycrypto/
.. _gmpy: http://code.google.com/p/gmpy/
.. _seccure: http://point-at-infinity.org/seccure/
.. _zxcvbn: https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/
.. _FORMAT.md: doc/FORMAT.md
.. _MacPorts: https://www.macports.org

.. image:: https://travis-ci.org/bwesterb/pol.png
   :target: https://travis-ci.org/bwesterb/pol
