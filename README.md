pol
===

**WARNING** pol is a young project, there might be errors,
even vulnerabilities --- please help out by testing
or reviewing its code.

pol /pɵl/ is a password manager with two important features:

   1. A nice interface.  Want to generate a password?
      
      ```
      $ pol generate github "my username is John Doo"
      Enter (append-)password: 
      Copied password to clipboard.  Press any key to clear ...
      ```
      
      Want to use the password?
      
      ```
      $ pol copy github
      Enter password: 
       note: 'my username is John Doo'
      Copied secret to clipboard.  Press any key to clear ...
      ```
      
   2. Hidden containers.  You can have multiple containers with different
      passwords.  Even if an adversary has multiple versions of your safe
      and a password of one of the containers, he cannot prove that there
      are more containers.

Getting started
------------

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
Then, create a new safe with `pol init`.

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

[![Build Status](https://travis-ci.org/bwesterb/pol.png)](
   https://travis-ci.org/bwesterb/pol)
      
<!-- vim: set shiftwidth=4:tabstop=4:expandtab: -->
