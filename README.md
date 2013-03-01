pol
===

**WARNING** pol is in development: it is not finished and not yet secure

pol /pɵl/ is a password manager with two important features:

   1. A nice interface.  Want to generate a password?

      ```
      $ pol generate github -n "my username is John Doo"
      Enter (append-)password [ default container ]:
      Copied generated password to clipboard.  Press any key to clear clipboard ...
      ```

      Want to use the password?

      ```
      $ pol copy github
          Enter password:
  
          Found 'github':
          
             my username is John Doo
  
          Copied secret to clipboard.  Press any key to clear clipboard ...
      ```

   2. Hidden containers.  You can have multiple containers with different
      passwords.  Even if an adversary has multiple versions of your safe
      and a password of one of the containers, he cannot prove that there
      are more containers.
      
<!-- vim: set shiftwidth=4:tabstop=4:expandtab: -->
