#!/usr/bin/env python

""" Entry point of the console application.

    Contains the argument parser and CLI interaction. """

import argparse
import logging
import os.path
import getpass
import pprint
import sys

import pol.safe
import pol.progressbar

class Program(object):
    def parse_args(self, argv):
        parser = argparse.ArgumentParser()
        parser.add_argument('--workers', '-w', type=int, metavar='N',
                    help='Number of workers processes (/threads)')
        parser.add_argument('--threads', '-t', action='store_true',
                    help='Use worker threads instead of processes')
        parser.add_argument('--safe', '-s', type=str, default='~/.pol',
                            metavar='PATH',
                    help='Path to safe')
        parser.add_argument('--verbose', '-v', action='count', dest='verbosity',
                    help='Add these to make pol chatty')
        parser.add_argument('--profile', '-p', action='store_true',
                    help='Profile performance of main process')
        subparsers = parser.add_subparsers(title='commands')

        p_init = subparsers.add_parser('init',
                    help='Create a new safe')
        p_init.add_argument('--ncontainers', '-n', type=int, default=1,
                    help='Initial number of containers')
        p_init.add_argument('--rerand-bits', '-R', type=int, default=1025,
                    help='Minimal size in bits of prime used for '+
                            'rerandomization')
        p_init.add_argument('--precomputed-group-parameters', '-P',
                        action='store_true', dest='precomputed_gp',
                    help='Use precomputed group parameters for rerandomization')
        p_init.set_defaults(func=self.cmd_init)

        p_list = subparsers.add_parser('list',
                    help='List entries')
        p_list.set_defaults(func=self.cmd_list)

        p_touch = subparsers.add_parser('touch',
                    help='Rerandomizes blocks')
        p_touch.set_defaults(func=self.cmd_touch)

        p_raw = subparsers.add_parser('raw',
                    help='Shows raw data of safe')
        p_raw.add_argument('--blocks', '-b', action='store_true', dest='blocks',
                    help='Also print blocks')
        p_raw.set_defaults(func=self.cmd_raw)

        self.args = parser.parse_args(argv)

    def main(self, argv):
        # Parse arguments
        self.parse_args(argv)

        # Set up logging
        if self.args.verbosity >= 2:
            level = logging.DEBUG
        elif self.args.verbosity == 1:
            level = logging.INFO
        else:
            level = logging.WARNING
        logging.basicConfig(level=level)

        # Profile?
        if self.args.profile:
            import yappi
            yappi.start()

        # Execute command
        ret = self.args.func()

        if self.args.profile:
            yappi.print_stats()

        return ret

    def cmd_init(self):
        # TODO add sanity checks for rerand_bits and nworkers
        progressbar = pol.progressbar.ProbablisticProgressBar()
        progressbar.start()
        def progress(step, x):
            if step == 'p' and x is None:
                progressbar.start()
            elif step == 'p' and x:
                progressbar(x)
            elif step == 'g':
                progressbar.end()
        safe = pol.safe.Safe.generate(nworkers=self.args.workers,
                                      gp_bits=self.args.rerand_bits,
                                      progress=progress,
                                      precomputed_gp=self.args.precomputed_gp,
                                      use_threads=self.args.threads)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)
    
    def cmd_touch(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        progressbar = pol.progressbar.ProgressBar()
        progressbar.start()
        def progress(v):
            progressbar(v)
            if v == 1.0:
                progressbar.end()
        safe.rerandomize(nworkers=self.args.workers,
                         use_threads=self.args.threads,
                         progress=progress)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)

    def cmd_raw(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        d = safe.data
        if not self.args.blocks:
            del d['blocks']
        pprint.pprint(d)

    def cmd_list(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        safe.open(getpass.getpass('Enter (list-)password: '))

def entrypoint(argv):
    return Program().main(argv)

if __name__ == '__main__':
    sys.exit(entrypoint(sys.argv[1:]))
