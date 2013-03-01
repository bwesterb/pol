#!/usr/bin/env python

""" Entry point of the console application.

    Contains the argument parser and CLI interaction. """

import argparse
import logging
import os.path
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
                    help='Path to safe')
        subparsers = parser.add_subparsers(title='commands')

        p_init = subparsers.add_parser('init',
                    help='Create a new safe')
        p_init.add_argument('--ncontainers', '-n', type=int, default=1,
                    help='Initial number of containers')
        p_init.set_defaults(func=self.cmd_init)

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
        safe = pol.safe.Safe.generate(nthreads=self.args.threads)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)
    
    def cmd_touch(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        safe.rerandomize(nthreads=self.args.threads)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)

if __name__ == '__main__':
    sys.exit(Program().main())
