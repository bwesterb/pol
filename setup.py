#!/usr/bin/env python

from setuptools import setup
from get_git_version import get_git_version

setup(
    name='pol',
    version=get_git_version(),
    description='pol, a modern password manager',
    author='Bas Westerbaan',
    author_email='bas@westerbaan.name',
    url='http://github.com/bwesterb/pol/',
    packages=['pol', 'pol.tests', 'pol.importers'],
    package_dir={'pol': 'src'},
    license='GPL 3.0',
    install_requires = [
        'pycrypto >=2.6',        # TODO do we need this version
        'msgpack-python >=0.2',  #      ibidem
        'gmpy >=1.15, <2',       #      ibidem
        'scrypt >=0.5.5',        #      ibidem
        'yappi >=0.62',          #      ibidem
        'python-mcrypt >=1.1',   #      ibidem
        'lockfile >=0.8',        #      ibidem
        ],
    entry_points = {
        'console_scripts': [
                'pol = pol.main:entrypoint',
            ]
        },
    classifiers = [
            'Development Status :: 3 - Alpha',
            'Environment :: Console',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Operating System :: POSIX',
            'Topic :: Security',
        ],
    test_suite='pol.tests',
    ),
