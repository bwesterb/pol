#!/usr/bin/env python

import os
import sys
import os.path

from setuptools import setup

from src._version import __version__

install_requires = [
    'pycrypto >=2.6',        # TODO do we need this version
    'msgpack-python >=0.2',  #      ibidem
    'gmpy2 >=2',             #      ibidem
    'yappi >=0.62',          #      ibidem
    'lockfile >=0.8',        #      ibidem
    'PyYAML >=3.08',
    'pyparsing >=2.3',       #      ibidem
    'zxcvbn >=4.0',
    'seccure >=0.4.0',
    'demandimport >=0.3.4',
    'argon2-cffi >=16.1.0',
    'urwid >=1.3.0',
    'fuzzywuzzy >=0.10.0',
        ]

base_path = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(base_path, 'README.rst')) as f:
    with open(os.path.join(base_path, 'CHANGES.rst')) as g:
        long_description = '{0}\n{1}'.format(f.read(), g.read())

setup(
    name='pol',
    version=__version__,
    description='pol, a modern password manager',
    long_description=long_description,
    author='Bas Westerbaan',
    author_email='bas@westerbaan.name',
    url='https://github.com/bwesterb/pol',
    zip_safe=False,
    packages=['pol',
              'pol.tests',
              'pol.passgen',
              'pol.editor',
              'pol.importers'],
    package_dir={'pol': 'src'},
    package_data={'pol': [
                    'editor/editfile.vim']},
    license='GPL 3.0',
    install_requires=install_requires,
    extras_require = {
        'psafe3-importer': ['twofish'],
        'scrypt': ['scrypt >=0.5.5, !=0.6.0, !=0.6.1'],
    },
    entry_points = {
        'console_scripts': [
                'pol = pol.main:entrypoint',
            ]
        },
    classifiers = [
            'Development Status :: 4 - Beta',
            'Environment :: Console',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Operating System :: POSIX',
            'Topic :: Security',
        ],
    test_suite='pol.tests',
    ),
