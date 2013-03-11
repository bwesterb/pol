#!/usr/bin/env python

""" Entry point of the console application.

    Contains the argument parser and CLI interaction. """

import argparse
import logging
import os.path
import getpass
import sys

import pol.safe
import pol.progressbar

class Program(object):
    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--threads', '-t', type=int, metavar='N',
                    help='Number of worker threads')
        parser.add_argument('--safe', '-s', type=str, default='~/.pol',
                            metavar='PATH',
                    help='Path to safe')
        parser.add_argument('--verbose', '-v', action='count', dest='verbosity',
                    help='Add these to make pol chatty')
        subparsers = parser.add_subparsers(title='commands')

        p_init = subparsers.add_parser('init',
                    help='Create a new safe')
        p_init.add_argument('--ncontainers', '-n', type=int, default=1,
                    help='Initial number of containers')
        p_init.add_argument('--rerand-bits', '-R', type=int, default=1024,
                    help='Minimal size in bits of prime used for '+
                            'rerandomization')
        p_init.set_defaults(func=self.cmd_init)

        p_list = subparsers.add_parser('list',
                    help='List entries')
        p_list.set_defaults(func=self.cmd_list)

        p_touch = subparsers.add_parser('touch',
                    help='Rerandomizes blocks')
        p_touch.set_defaults(func=self.cmd_touch)

        self.args = parser.parse_args()

    def main(self):
        # Parse arguments
        self.parse_args()

        # Set up logging
        if self.args.verbosity >= 2:
            level = logging.DEBUG
        elif self.args.verbosity == 1:
            level = logging.INFO
        else:
            level = logging.WARNING
        logging.basicConfig(level=level)

        # Execute command
        return self.args.func()

    def cmd_init(self):
        # TODO add sanity checks for rerand_bits and nthreads
        progressbar = pol.progressbar.ProbablisticProgressBar()
        def progress(step, x):
            if step == 'p' and x is None:
                progressbar.start()
            elif step == 'p' and x:
                progressbar(x)
            elif step == 'g':
                progressbar.end()
        safe = pol.safe.Safe.generate(nthreads=self.args.threads,
                                      gp_bits=self.args.rerand_bits,
                                      progress=progress)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)
    
    def cmd_touch(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        safe.rerandomize(nthreads=self.args.threads)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)

    def cmd_list(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        safe.open(getpass.getpass('Enter (list-)password: '))

def entrypoint():
    sys.exit(Program().main())

if __name__ == '__main__':
    entrypoint()
