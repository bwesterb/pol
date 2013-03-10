#!/usr/bin/env python

""" Entry point of the console application.

    Contains the argument parser and CLI interaction. """

import argparse
import logging
import os.path
import getpass
import sys

import pol.safe

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
        def progress(step, x):
            # TODO this is a stub
            if step == 'gp':
                width = 80
                p95 = int(min(x.n / x.n95, 1) * width)
                p50 = int(min(x.n / x.n50, 1) * width)
                p5 = int(min(x.n / x.n5, 1) * width)
                b95 = p95
                b50 = p50 - p95
                b5 = p5 - p50
                sys.stdout.write('#'*b95 + '='*b50 + '-'*b5 + '\b'*width)
                sys.stdout.flush()
        safe = pol.safe.Safe.generate(nthreads=self.args.threads,
                                      gp_bits=self.args.rerand_bits,
                                      progress=progress)
        print
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
