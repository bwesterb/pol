pol
===

**WARNING** pol is a young project, there might be errors,
even vulnerabilities --- please help out by testing
or reviewing its code.

pol /pɵl/ is a password manager with two important features:

   1. A nice commandline interface.  Want to generate a password?
      Just type:
      
        $ pol generate github "my username is John Doo"
        Enter (append-)password: 
        Copied password to clipboard.  Press any key to clear ...
      
      This will generate a new password; copy it to the clipboard and
      store it under the key *github* with the
      note *my username is John Doo*.
      
      Want to retrieve the password you just stored?  Just type:
      
        $ pol copy github
        Enter password: 
         note: 'my username is John Doo'
        Copied secret to clipboard.  Press any key to clear ...

      See below for a description of all commands.
      
   2. Hidden containers.  The best way to keep a secret, is
      being able to deny you are keeping one.  Sometimes you
      are forced to give up your passwords.  For instance,
      by a criminal, government or employer.
      Luckily a pol safe can have multiple
      containers.  Each container is opened by its own passwords.
      If someone does not have a password of a container, he cannot
      prove the existence of the container in any way.
      Thus if you are forced to open your pol safe, you can give
      a password to an uninteresting container and keep your real
      secrets safe.

Getting started
---------------

### Installation
First, we install pol.

#### On Debian Wheezy

    $ sudo apt-get install libgmp3-dev libmcrypt-dev build-essential \
                            python-dev python-pip
    $ sudo pip install pol

#### On Ubuntu 13.04

    $ sudo apt-get install libgmp-dev libmcrypt-dev build-essential python-dev \
                        python-pip libssl-dev
    $ sudo pip install pol

#### On Mac with MacPorts

Install [MacPorts](http://www.macports.org).  Then run

    $ sudo port install gmp mcrypt py-pip py27-mcrypt py27-crypto
    $ sudo pip-2.7 install pol

If you get `pol: command not found` when you try to run `pol`,
add `/opt/local/Library/Frameworks/Python.framework/Versions/2.7/bin`
to your `PATH`.  For instance, like this:

    $ echo 'export PATH=/opt/local/Library/Frameworks/Python.framework/Versions/2.7/bin:$PATH' >> ~/.profile

#### Compiled binaries for Mac

You can find compiled binaries, created using pyinstaller, for
OS X [here](http://westerbaan.name/~bas/pol/pol-latest.zip).
Extract the zip somewhere, say `/opt/pol`, and add the directory to your `PATH`.

### Creating a safe
Then, we create a new safe with `pol init`.  `pol` will ask you for the
passwords of your containers.

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
      Leave blank if you do not want an append-passowrd.
    
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

### generate a new password

This will generate a new password, copy it to your clipboard and store it under
the key `facebook`.

    $ pol generate facebook
    Enter (append-)password: 
    Copied password to clipboard.  Press any key to clear ...

You might want to add a note.  This note is shown when you retrieve the password.

    $ pol generate facebook "e-mail: john@doo.org"
    Enter (append-)password: 
    Copied password to clipboard.  Press any key to clear ...

If you just want a password, but do not want to store it, omit the key:

    $ pol generate
    Copied password to clipboard.  Press any key to clear ...

If you want to write it to the screen, add `--stdout`:

    $ pol generate --stdout
    $^NxY{&Fsy,&->Gi$RZ}

There are several options to change the style of the password:

    # xkcd style password with 40 bits of entropy
    $ pol generate --stdout --kind english --entropy 40
    dirty papal nephew repair
    
    # alphanumeric password that would take ages to bruteforce with 10 tries per second
    $ pol generate --sdtout --kind alphanum --web-crack-time ages
    NNrZ9g8Sy

For all options, see `pol generate -h`.


[![Build Status](https://travis-ci.org/bwesterb/pol.png)](
   https://travis-ci.org/bwesterb/pol)
      
<!-- vim: set shiftwidth=4:tabstop=4:expandtab: -->
