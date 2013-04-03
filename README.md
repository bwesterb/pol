pol
===

**WARNING** pol is in development: it is not finished and not yet secure

pol /pɵl/ is a password manager with two important features:

   1. A nice interface.  Want to generate a password?
      
      ```
      $ pol generate github -n "my username is John Doo"
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

Installation
------------

### On Ubuntu

    $ apt-get install libgmp-dev libmcrypt-dev build-essential python-dev \
                        python-pip
    $ pip install pol

### On Mac with MacPorts

    $ port install gmp mcrypt
    $ pip install pol

[![Build Status](https://travis-ci.org/bwesterb/pol.png)](
   https://travis-ci.org/bwesterb/pol)
      
<!-- vim: set shiftwidth=4:tabstop=4:expandtab: -->
