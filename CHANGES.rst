pol Changelog
=============

0.3.7.1 (2016-01-03)
--------------------

 - Add new key-stretcher ``argon2``.

   It is the winner of the recent `Password Hashing Competition
   <https://password-hashing.net>`_ .  To use ``argon2`` instead of
   the current default ``scrypt``, create a safe with ``pol init --argon2``.


0.3.6 (2016-01-03)
------------------

 - Rerandomize in background to return shell earlier.
 - Use static __version__ attribute.
 - Use RST for README.
 - Use the ``twofish`` module instead of ``mcrypt``.
