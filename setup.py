#!/usr/bin/env python

import sys
from setuptools import setup
from src.version import get_version

install_requires = [
    'pycrypto >=2.6',        # TODO do we need this version
    'msgpack-python >=0.2',  #      ibidem
    'gmpy >=1.15, <2',       #      ibidem
    'scrypt >=0.5.5, !=0.6.0, !=0.6.1',#      ibidem
    'yappi >=0.62',          #      ibidem
    'lockfile >=0.8',        #      ibidem
    'PyYAML >=3',            #      ibidem
    'pyparsing >=1.5.6, <2.0.0', #   ibidem
    'zxcvbn >=1.0',
    'seccure >=0.2.3',
    'demandimport >=0.2.1',
        ]

if sys.version_info < (2, 7):
    install_requires.append('argparse >= 0.8')

setup(
    name='pol',
    version=get_version(),
    description='pol, a modern password manager',
    author='Bas Westerbaan',
    author_email='bas@westerbaan.name',
    url='https://getpol.org',
    packages=['pol',
              'pol.tests',
              'pol.version',
              'pol.passgen',
              'pol.editor',
              'pol.importers'],
    package_dir={'pol': 'src'},
    package_data={'pol': [
                    'editor/editfile.vim']},
    license='GPL 3.0',
    install_requires=install_requires,
    extras_require = {
        'psafe3-importer': ['python-mcrypt >=1.1']
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
            'Operating System :: POSIX',
            'Topic :: Security',
        ],
    test_suite='pol.tests',
    ),
