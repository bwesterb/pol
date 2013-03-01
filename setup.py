#!/usr/bin/env python

from setuptools import setup

setup(name='pol',
    description='pol, a modern password manager',
    author='Bas Westerbaan',
    author_email='bas@westerbaan.name',
    url='http://github.com/bwesterb/pol/',
    packages=['pol'],
    package_dir={'pol': 'src'},
    install_requires = [
        'pycrypto>=2.6',        # TODO do we need this version
        'msgpack-python>=0.2',  #      ibidem 
        'gmpy2-2.0.0>=b4',      #      ibidem 
        ]
    )
