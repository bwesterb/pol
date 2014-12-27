#!/usr/bin/env python

""" Entry point of the console application.

    Contains the argument parser and CLI interaction. """

# demandimport delays the import of modules until they are actually used.
import os
import sys
import demandimport

# FIXME the pyinstaller module loader breaks when running multiple processes
#       and demandimport is enabled.  Thus, when we are frozen by pyinstaller,
#       we disable demandimport.
if hasattr(sys, 'frozen'):
    import multiprocessing
elif 'POL_NO_DEMANDIMPORT' not in os.environ:
    demandimport.ignore('Crypto.PublicKey._fastmath')
    demandimport.enable()

import traceback
import readline
import argparse
import logging
import os.path
import getpass
import pprint
import shlex
import time
import math
import csv
import re
import os

import pol.text
import pol.safe
import pol.passgen
import pol.version
import pol.terminal
import pol.humanize
import pol.clipboard
import pol.progressbar

import pol.importers.keepass
import pol.importers.psafe3
import pol.editfile
import pol.editor
import pol.speed

import msgpack
import yappi
import yaml

l = logging.getLogger(__name__)


# Used among others by `pol generate --hash-crack-time years'
cracktime_names = ('seconds', 'minutes', 'hours', 'days', 'months', 'years',
                   'decades', 'centuries', 'millennia', 'ages', 'astronomical')
cracktimes = {'seconds':     10,
              'minutes':     10*60,
              'hours':       10*60*60,
              'days':        10*60*60*24,
              'months':      10*60*60*24*30,
              'years':       10*60*60*24*365,
              'decades':     10*60*60*24*365*10,
              'centuries':   10*60*60*24*365*100,
              'millennia':   10*60*60*24*365*1000,
              'ages':        10*60*60*24*365*1000000,
              'astronomical':10*60*60*24*365*1000000000}

# TODO add commands
#   pol rename
#       regenerate
#       change-password

class Program(object):
    def __init__(self):
        # Contents of keyfiles, if provided
        self.additional_keys = None

    def parse_args(self, argv):
        """ Parse command line arguments.  Sets self.args. """
        # Common
        parser = argparse.ArgumentParser(add_help=False)
        g_basic = parser.add_argument_group('basic options')
        g_basic.add_argument('--safe', '-s', type=str,
                            metavar='PATH',
                    help='Path to safe')
        g_basic.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        g_basic.add_argument('--verbose', '-v', action='count',
                            dest='verbosity',
                    help='Add these to make pol chatty')
        g_basic.add_argument('--version', '-V', action=Program._VersionAction,
                            nargs=0,
                    help='Print version of pol and quit')
        g_advanced = parser.add_argument_group('advanced options')
        g_advanced.add_argument('--workers', '-w', type=int, metavar='N',
                    help='Number of workers processes (/threads)')
        g_advanced.add_argument('--threads', '-t', action='store_true',
                    help='Use worker threads instead of processes')
        g_advanced.add_argument('--profile', '-p', action='store_true',
                    help='Profile performance of main process')
        g_advanced.add_argument('--config-file', '-C', type=str, metavar='PATH',
                    help='Path to pol configuration file.')
        subparsers = parser.add_subparsers(title='commands')

        # pol init
        p_init = subparsers.add_parser('init', add_help=False,
                    help='Create a new safe')
        p_init_b = p_init.add_argument_group('basic options')
        p_init_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_init_b.add_argument('--force', '-f', action='store_true',
                    help='Remove any existing safe')
        p_init_a = p_init.add_argument_group('advanced options')
        p_init_a.add_argument('--rerand-bits', '-R', type=int, default=1025,
                    help='Minimal size in bits of prime used for '+
                            'rerandomization')
        p_init_a.add_argument('--precomputed-group-parameters', '-P',
                        action='store_true', dest='precomputed_gp',
                    help='Use precomputed group parameters for rerandomization')
        p_init_a.add_argument('--passwords', '-p', nargs='+', metavar='PW',
                    help='Passwords for containers as normally input '+
                            'interactively')
        p_init_a.add_argument('--i-know-its-unsafe', action='store_true',
                    help='Required for obviously unsafe actions')
        p_init_a.add_argument('--blocks', '-N', type=int, default=1024,
                    help='Number of blocks in the safe')
        p_init_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_init.set_defaults(func=self.cmd_init)

        # pol list
        p_list = subparsers.add_parser('list', add_help=False,
                    help='List entries')
        p_list_b = p_list.add_argument_group('basic options')
        p_list_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_list_b.add_argument('regex', nargs='?',
                    help='Only show entries with keys matching this regex')
        p_list_a = p_list.add_argument_group('basic options')
        p_list_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to list')
        p_list_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_list.set_defaults(func=self.cmd_list)

        # pol generate
        p_generate = subparsers.add_parser('generate', add_help=False,
                    help='Generate and store a password')
        p_generate.add_argument('key', nargs='?', default=None)
        p_generate_b = p_generate.add_argument_group('basic options')
        p_generate_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_generate_b.add_argument('note', nargs='?')
        p_generate_b.add_argument('--stdout', '-s', action='store_true',
                    help='write password to stdout')
        p_generate_b.add_argument('--no-copy', '-N', action='store_true',
                    help='Do not copy secret to clipboard.')
        p_generate_b.add_argument('--kind', '-k', default='dense',
                    choices=pol.passgen.kinds,
                    help='Kind of password to generate.')
        p_generate_s = p_generate_b.add_mutually_exclusive_group()
        p_generate_s.add_argument('--entropy', '-e', type=int, default=None,
                                metavar='N',
                    help='Desired strength of password')
        p_generate_s.add_argument('--length', '-l', type=int, default=None,
                                metavar='N',
                    help='Desired length of password')
        p_generate_s.add_argument('--web-crack-time', '-w',
                    choices=cracktime_names,
                    help=('Desired minimal time to brute force when '+
                            'allowed one try per second'))
        p_generate_s.add_argument('--hash-crack-time', '-H',
                    choices=cracktime_names,
                    help=('Desired minimal time to brute force when '+
                            'allowed a billion tries per second'))
        p_generate_s.add_argument('--sha-crack-cost', '-S', type=int,
                    metavar='DOLLARS',
                    help=('Desired minimal amount of dollars required to '+
                            'brute force if hashed with SHA-256'))
        p_generate_a = p_generate.add_argument_group('advanced options')
        p_generate_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to add password to')
        p_generate_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_generate.set_defaults(func=self.cmd_generate)

        # pol paste
        p_paste = subparsers.add_parser('paste', add_help=False,
                    help='Stores a secret from the clipboard')
        p_paste.add_argument('key')
        p_paste_b = p_paste.add_argument_group('basic options')
        p_paste_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_paste_b.add_argument('note', nargs='?')
        p_paste_a = p_paste.add_argument_group('advanced options')
        p_paste_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to add secret to')
        p_paste_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_paste.set_defaults(func=self.cmd_paste)

        # pol copy
        p_copy = subparsers.add_parser('copy', add_help=False,
                    help='Copies a password to the clipboard')
        p_copy.add_argument('key')
        p_copy_b = p_copy.add_argument_group('basic options')
        p_copy_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_copy_b.add_argument('-n', '--number', type=int, metavar='N',
                                default=None,
                    help='Pick, if multiple entries match, the Nth')
        p_copy_a = p_copy.add_argument_group('advanced options')
        p_copy_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to copy secret from')
        p_copy_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_copy.set_defaults(func=self.cmd_copy)

        # pol put
        p_put = subparsers.add_parser('put', add_help=False,
                    help='Stores a secret')
        p_put.add_argument('key')
        p_put_b = p_put.add_argument_group('basic options')
        p_put_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_put_b.add_argument('note', nargs='?')
        p_put_b.add_argument('--secret', '-s',
                    help='The secret to store.  If none is specified, reads '+
                         'secret from stdin.')
        p_put_a = p_put.add_argument_group('advanced options')
        p_put_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to add secret to')
        p_put_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_put.set_defaults(func=self.cmd_put)

        # pol get
        p_get = subparsers.add_parser('get', add_help=False,
                    help='Write secret to stdout')
        p_get.add_argument('key')
        p_get_b = p_get.add_argument_group('basic options')
        p_get_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_get_b.add_argument('-n', '--number', type=int, metavar='N',
                                default=None,
                    help='Pick, if multiple entries match, the Nth')
        p_get_a = p_get.add_argument_group('advanced options')
        p_get_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to get secret from')
        p_get_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_get.set_defaults(func=self.cmd_get)

        # pol remove
        p_remove = subparsers.add_parser('remove', add_help=False,
                    help='Removes an entry')
        p_remove.add_argument('key')
        p_remove_b = p_remove.add_argument_group('basic options')
        p_remove_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_remove_b.add_argument('-n', '--number', type=int, metavar='N',
                                default=None,
                    help='Pick, if multiple entries match, the Nth')
        p_remove_a = p_remove.add_argument_group('advanced options')
        p_remove_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to remove entry from')
        p_remove_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_remove.set_defaults(func=self.cmd_remove)

        # pol edit
        p_edit = subparsers.add_parser('edit', add_help=False,
                    help='Edit entries in a texteditor')
        p_edit_b = p_edit.add_argument_group('basic options')
        p_edit_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_edit_b.add_argument('regex', nargs='?',
                    help='Only edit entries with keys matching this regex')
        p_edit_b.add_argument('-s', '--secrets', action='store_true',
                    help='Edit the secrets, instead of hiding them')
        p_edit_b.add_argument('-m', '--multiple', action='store_true',
                    help='Enter more than one password to edit multiple containers')
        p_edit_a = p_edit.add_argument_group('basic options')
        p_edit_a.add_argument('--passwords', '-p', metavar='PW', nargs='+',
                    help='Password(s) of the container(s) to edit')
        p_edit_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_edit.set_defaults(func=self.cmd_edit)

        # pol touch
        p_touch = subparsers.add_parser('touch', add_help=False,
                    help='Rerandomizes blocks')
        p_touch_b = p_touch.add_argument_group('basic options')
        p_touch_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_touch.set_defaults(func=self.cmd_touch)

        # pol raw
        p_raw = subparsers.add_parser('raw', add_help=False,
                    help='Shows raw data of safe')
        p_raw.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_raw.add_argument('--blocks', '-b', action='store_true',
                    help='Also print raw blocks')
        p_raw.add_argument('--passwords', '-p', nargs='+', metavar='PW',
                    help='Also show data of containers opened by '+
                            'these passwords')
        p_raw.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_raw.set_defaults(func=self.cmd_raw)

        # pol import-psafe3
        p_import_psafe3 = subparsers.add_parser('import-psafe3', add_help=False,
                    help='Imports entries from a psafe3 db')
        p_import_psafe3.add_argument('path',
                    help='Path to psafe3 database')
        p_import_psafe3_b = p_import_psafe3.add_argument_group(
                                    'basic options')
        p_import_psafe3_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_import_psafe3_a = p_import_psafe3.add_argument_group(
                                    'advanced options')
        p_import_psafe3_a.add_argument('-K', '--keyfiles', nargs='*',
                            metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_import_psafe3.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to import to')
        p_import_psafe3.add_argument('--psafe3-password', '-P',
                    metavar='PASSWORD',
                    help='Password of psafe3 db to import')
        p_import_psafe3.set_defaults(func=self.cmd_import_psafe3)

        # pol import-keepass
        p_import_keepass = subparsers.add_parser('import-keepass',
                        add_help=False,
                    help='Imports entries from a KeePass 1.x db')
        p_import_keepass.add_argument('path',
                    help='Path to KeePass database')
        p_import_keepass_b = p_import_keepass.add_argument_group(
                                    'basic options')
        p_import_keepass_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_import_keepass_b.add_argument('-k', '--keepass-keyfile',
                            metavar='PATH',
                    help='Keyfile used to open KeePass database')
        p_import_keepass_a = p_import_keepass.add_argument_group(
                                    'advanced options')
        p_import_keepass_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to import to')
        p_import_keepass_a.add_argument('--keepass-password', '-P',
                    metavar='PASSWORD',
                    help='Password of KeePass db to import')
        p_import_keepass_a.add_argument('-K', '--keyfiles', nargs='*',
                        metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_import_keepass.set_defaults(func=self.cmd_import_keepass)

        # pol export
        p_export = subparsers.add_parser('export',
                        add_help=False,
                    help='Exports entries to CSV')
        p_export.add_argument('path',
                    help='Path to CSV file to write to.  Defaults to stdout.',
                    default='-', nargs='?')
        p_export_b = p_export.add_argument_group('basic options')
        p_export_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_export_b.add_argument('-f', '--force', action='store_true',
                    help='Overwrite existing file')
        p_export_a = p_export.add_argument_group('advanced options')
        p_export_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to export')
        p_export_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_export.set_defaults(func=self.cmd_export)

        # pol import
        p_import = subparsers.add_parser('import',
                        add_help=False,
                    help='Imports entries from CSV')
        p_import.add_argument('path',
                    help='Path to CSV file to read.  Defaults to stdin.',
                    default='-', nargs='?')
        p_import_b = p_import.add_argument_group('basic options')
        p_import_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_import_a = p_import.add_argument_group('advanced options')
        p_import_a.add_argument('--password', '-p', metavar='PASSWORD',
                    help='Password of container to import to')
        p_import_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_import.set_defaults(func=self.cmd_import)

        # pol shell
        p_shell = subparsers.add_parser('shell',
                        add_help=False,
                    help='Start interactive shell')
        p_shell_b = p_shell.add_argument_group(
                                    'basic options')
        p_shell_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_shell_a = p_shell.add_argument_group('advanced options')
        p_shell_a.add_argument('-K', '--keyfiles', nargs='*', metavar='PATH',
                    help='Compose passwords with the contents of these files')
        p_shell.set_defaults(func=self.cmd_shell)

        # pol speed
        p_speed = subparsers.add_parser('speed',
                        add_help=False,
                    help='Measures speed of the components of pol')
        p_speed_b = p_speed.add_argument_group(
                                    'basic options')
        p_speed_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_speed.set_defaults(func=self.cmd_speed)

        p_nop = subparsers.add_parser('nop',
                        add_help=False,
                    help='Does nothing')
        p_nop_b = p_nop.add_argument_group(
                                    'basic options')
        p_nop_b.add_argument('-h', '--help', action='help',
                    help='show this help message and exit')
        p_nop_b.set_defaults(func=self.cmd_nop)

        self.args = parser.parse_args(argv)

    def load_configuration(self):
        """ Loads the configuration file, if present, and sets self.config """
        path = (self.args.config_file if self.args.config_file
                    else os.path.expanduser('~/.polrc'))
        if not os.path.exists(path):
            if self.args.config_file:
                sys.stderr.write("%s: no such file\n" % path)
                return -17
            l.debug('No configuration file found.')
            self.config = {}
            return
        cached_path = path + '.cached'
        if (os.path.exists(cached_path)
                    and os.stat(cached_path).st_mtime
                            > os.stat(path).st_mtime):
            l.debug('Loading cached configuration file %s ...', cached_path)
            with open(cached_path) as f:
                try:
                    self.config = msgpack.load(f)
                    l.debug('    ... done')
                    return
                except Exception as e:
                    l.warning('Exception loading cached configuration file.  '+
                                'Loading original.  (%s)', e)
        l.debug('Loading configuration file %s ...', path)
        with open(path) as f:
            try:
                self.config = yaml.load(f)
                if not self.config:
                    self.config = {}
            except yaml.YAMLError as e:
                sys.stderr.write("%s: error in configuration file:\n%s\n" % (
                                path, e))
                return -18
        l.debug('Writing cached configuration file %s ...', cached_path)
        with open(cached_path, 'w') as f:
            msgpack.dump(self.config, f)

    def main(self, argv):
        """ Main entry point. """
        try:
            profiling = False

            if 'POL_PROFILE' in os.environ:
                profiling = True
                yappi.start()

            if not argv:
                argv = ['shell']

            # Parse arguments
            self.parse_args(argv)

            # Profile?
            if self.args.profile and not profiling:
                profiling = True
                yappi.start()

            # Set up logging
            extra_logging_config = {}
            if self.args.verbosity >= 2:
                level = logging.DEBUG
                extra_logging_config['format'] = ('%(relativeCreated)d '+
                        '%(levelname)s %(name)s %(message)s')
            elif self.args.verbosity == 1:
                level = logging.INFO
            else:
                level = logging.WARNING
            logging.basicConfig(level=level, **extra_logging_config)

            # Load configuration
            ret = self.load_configuration()
            if ret:
                return ret

            # Set some global state
            self.safe_path = (self.args.safe if self.args.safe
                                else (self.config['safe']
                                        if 'safe' in self.config
                                    else os.path.expanduser('~/.pol')))
            self.keyfiles = (self.args.keyfiles if
                                    hasattr(self.args, 'keyfiles') and
                                            self.args.keyfiles
                                else (self.config['keyfiles']
                                        if 'keyfiles' in self.config
                                    else None))

            # Execute command
            ret = self._run_command()

            if profiling:
                yappi.stop()
                yappi.print_stats()

            return ret
        except Exception:
            self._handle_uncaught_exception()

    def cmd_init(self):
        if (os.path.exists(self.safe_path) and not self.args.force):
            print '%s exists.  Use -f to override.' % self.safe_path
            return -10
        self._ensure_keyfiles_are_loaded()
        if self.args.rerand_bits < 1025 and not self.args.i_know_its_unsafe:
            print 'You should now use less than 1025b group parameters.'
            return -9
        if self.args.precomputed_gp and not self.args.i_know_its_unsafe:
            # TODO are 2049 precomputed group parameters safe?
            print 'You should now use precomputed group parameters.'
            return -9
        if self.args.passwords:
            interactive = False
            cmdline_pws = list(reversed(self.args.passwords))
        else:
            interactive = True
        if interactive:
            print "You are about to create a new safe.  A safe can have up to six"
            print "separate containers to store your secrets.  A container is"
            print "accessed by one of its passwords.  Without one of its passwords,"
            print "you cannot prove the existence of a container."
            print
        first = True
        second = False
        pws = []
        for i in xrange(1, 7):
            if interactive:
                if not first:
                    print
                print 'Container #%s' % i
                if first:
                    print "  Each container must have a master-password.  This password gives"
                    print "  full access to the container."
                    print
                if second:
                    print "  Now enter the passwords for the second container."
                    print "  Leave blank if you do not want a second container."
                    print
            if interactive:
                if first:
                    masterpw = pol.terminal.zxcvbn_getpass(
                            'Enter master-password: ', '    ', False)
                else:
                    masterpw = pol.terminal.zxcvbn_getpass(
                            'Enter master-password [stop]: ', '    ')
            else:
                masterpw = cmdline_pws.pop() if cmdline_pws else ''
            if not masterpw:
                break
            if interactive and first:
                print
                print "  A container can have a list-password.  With this password you can"
                print "  list and add entries.  You cannot see the secrets of the existing"
                print "  entries.  Leave blank if you do not want a list-password."
                print
            if interactive:
                listpw = pol.terminal.zxcvbn_getpass(
                            'Enter list-password [no list-password]: ', '    ')
            else:
                listpw = cmdline_pws.pop() if cmdline_pws else ''
            if interactive and first:
                print
                print "  A container can have an append-password.  With this password you"
                print "  can only add entries.  You cannot see the existing entries."
                print "  Leave blank if you do not want an append-password."
                print
            if interactive:
                appendpw = pol.terminal.zxcvbn_getpass(
                        'Enter append-password [no append-password]: ', '    ')
            else:
                appendpw = cmdline_pws.pop() if cmdline_pws else ''
            if second:
                second = False
            if first:
                first = False
                second = True
            pws.append((masterpw if masterpw else None,
                        listpw if listpw else None,
                        appendpw if appendpw else None))
        if interactive:
            print
        if not self.args.precomputed_gp:
            print 'Generating group parameters for this safe. This can take a while ...'
        # TODO generate group parameters in parallel
        progressbar = pol.progressbar.ProbablisticProgressBar()
        progressbar.start()
        def progress(step, x):
            if step == 'p' and x is None:
                progressbar.start()
            elif step == 'p' and x:
                progressbar(x)
            elif step == 'g':
                progressbar.end()
        try:
            blocks_per_container = int(math.floor(self.args.blocks / 6.0))
            with pol.safe.create(os.path.expanduser(self.safe_path),
                                 override=self.args.force,
                                 nworkers=self.args.workers,
                                 gp_bits=self.args.rerand_bits,
                                 progress=progress,
                                 precomputed_gp=self.args.precomputed_gp,
                                 use_threads=self.args.threads,
                                 n_blocks=self.args.blocks) as safe:
                for i, mlapw in enumerate(pws):
                    mpw, lpw, apw = mlapw
                    print '  allocating container #%s ...' % (i+1)
                    c = safe.new_container(mpw, lpw, apw,
                                    additional_keys=self.additional_keys,
                                    nblocks=blocks_per_container)
                print '  trashing freespace ...'
                safe.trash_freespace()
        except pol.safe.SafeAlreadyExistsError:
            print '%s exists.  Use -f to override.' % self.safe_path
            return -10

    def cmd_touch(self):
        with self._open_safe() as safe:
            safe.touch()

    def cmd_raw(self):
        with self._open_safe() as safe:
            d = dict(safe.data)
            if not self.args.blocks:
                del d['blocks']
            pprint.pprint(d)
            if not self.args.passwords:
                return
            for password in self.args.passwords:
                for container in self._open_containers(safe, password):
                    print
                    print 'Container %s' % container.id
                    if container.main_data:
                        pprint.pprint(container.main_data)
                    if container.append_data:
                        pprint.pprint(container.append_data)
                    if container.secret_data:
                        pprint.pprint(container.secret_data)

    def cmd_get(self):
        with self._open_safe() as safe:
            found_one = False
            entries = []
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter password: ')):
                if not found_one:
                    found_one = True
                try:
                    for entry in container.get(self.args.key):
                        if not entry.has_secret:
                            continue
                        entries.append((container, entry))
                except pol.safe.MissingKey:
                    continue
                except KeyError:
                    continue
            if not found_one:
                sys.stderr.write('The password did not open any container.\n')
                return -1
            if not entries:
                sys.stderr.write('No entries found.\n')
                return -4
            if len(entries) > 1 and not self.args.number:
                sys.stderr.write('Multiple entries found:\n')
                sys.stderr.write('\n')
                for n, container_entry in enumerate(entries):
                    container, entry = container_entry
                    sys.stderr.write(' %2s. %-20s %s\n' % (n+1, entry.key,
                            pol.text.escape_cseqs(entry.note) if entry.note
                            else ''))
                sys.stderr.write('\n')
                sys.stderr.write('Use `-n N\' to pick one.\n')
                return -8
            n = self.args.number - 1 if self.args.number else 0
            if n < 0 or n >= len(entries):
                sys.stderr.write('Entry number out of range.\n')
                return -15
            entry = entries[n][1]
            sys.stderr.write(' note: %s\n' % pol.text.escape_cseqs(entry.note)
                                                if entry.note else '')
            print entry.secret

    def cmd_remove(self):
        with self._open_safe() as safe:
            found_one = False
            entries = []
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter password: ')):
                if not found_one:
                    found_one = True
                try:
                    for entry in container.get(self.args.key):
                        if not entry.has_secret:
                            continue
                        entries.append((container, entry))
                except pol.safe.MissingKey:
                    continue
                except KeyError:
                    continue
            if not found_one:
                sys.stderr.write('The password did not open any container.\n')
                return -1
            if not entries:
                sys.stderr.write('No entries found.\n')
                return -4
            if len(entries) > 1 and not self.args.number:
                sys.stderr.write('Multiple entries found:\n')
                sys.stderr.write('\n')
                for n, container_entry in enumerate(entries):
                    container, entry = container_entry
                    sys.stderr.write(' %2s. %-20s %s\n' % (n+1, entry.key,
                            pol.text.escape_cseqs(entry.note) if entry.note
                                    else ''))
                sys.stderr.write('\n')
                sys.stderr.write('Use `-n N\' to pick one.\n')
                return -8
            n = self.args.number - 1 if self.args.number else 0
            if n < 0 or n >= len(entries):
                sys.stderr.write('Entry number out of range.\n')
                return -15
            entries[n][1].remove()

    def cmd_copy(self):
        if not pol.clipboard.available:
            print 'Clipboard access not available.'
            print 'Use `pol get\' to print secrets.'
            return -7
        with self._open_safe() as safe:
            found_one = False
            entries = []
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter password: ')):
                if not found_one:
                    found_one = True
                try:
                    for entry in container.get(self.args.key):
                        if not entry.has_secret:
                            continue
                        entries.append((container, entry))
                except pol.safe.MissingKey:
                    continue
                except KeyError:
                    continue
            if not found_one:
                print 'The password did not open any container.'
                return -1
            if not entries:
                print 'No entries found'
                return -4
            if len(entries) > 1 and not self.args.number:
                sys.stderr.write('Multiple entries found:\n')
                sys.stderr.write('\n')
                for n, container_entry in enumerate(entries):
                    container, entry = container_entry
                    sys.stderr.write(' %2s. %-20s %s\n' % (n+1, entry.key,
                            pol.text.escape_cseqs(entry.note) if entry.note
                                        else ''))
                sys.stderr.write('\n')
                sys.stderr.write('Use `-n N\' to pick one.\n')
                return -8
            n = self.args.number - 1 if self.args.number else 0
            if n < 0 or n >= len(entries):
                sys.stderr.write('Entry number out of range.\n')
                return -15
            entry = entries[n][1]
            print ' note: %s' % (pol.text.escape_cseqs(entry.note)
                                    if entry.note else '')
            print 'Copied secret to clipboard.  Press any key to clear ...'
            pol.clipboard.copy(entry.secret)
            pol.terminal.wait_for_keypress()
            pol.clipboard.clear()
    def cmd_paste(self):
        if not pol.clipboard.available:
            print 'Clipboard access not available.'
            print 'Use `pol put\' to add passwords from stdin.'
            return -7
        pw = pol.clipboard.paste()
        if not pw:
            print 'Clipboard is empty'
            return -3
        return self._store(pw)
        pol.clipboard.clear()
    def cmd_put(self):
        pw = self.args.secret if self.args.secret else sys.stdin.read()
        if not pw:
            print 'No secret given'
            return -3
        return self._store(pw)
    def _store(self, pw):
        """ Common code of `pol put', `pol generate' and `pol paste' -
            stores `pw' to an entry self.args.key. """
        with self._open_safe() as safe:
            found_one = False
            stored = False
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter (append-)password: ')):
                if not found_one:
                    found_one = True
                try:
                    container.add(self.args.key, self.args.note, pw)
                    container.save()
                    stored = True
                    break
                except pol.safe.MissingKey:
                    pass
            if not found_one:
                print 'The password did not open any container.'
                return -1
            if found_one and not stored:
                print 'No append access to the containers opened by this password'
                return -2
    def cmd_generate(self):
        if self.args.hash_crack_time:
            self.args.entropy = math.log(1000000000 * cracktimes[
                                        self.args.hash_crack_time], 2)
        if self.args.web_crack_time:
            self.args.entropy = math.log(cracktimes[
                                        self.args.web_crack_time], 2)
        if self.args.sha_crack_cost:
            self.args.entropy = math.log(self.args.sha_crack_cost
                                            * 500000000, 2)
            # We use the bitcoin mining rate as an estimator
            #   http://blockchain.info/stats
            # TODO keep up-to-date
        pw = pol.passgen.generate_password(length=self.args.length,
                                           entropy=self.args.entropy,
                                           kind=self.args.kind)
        if self.args.key is None:
            if self.args.stdout:
                sys.stdout.write(pw)
                sys.stdout.write("\n")
                return
            if self.args.no_copy:
                return
            if not pol.clipboard.available:
                sys.stderr.write('Clipboard access not available.\n')
                sys.stderr.write('Use --stdout to write to print password instead.\n')
                return -7
            pol.clipboard.copy(pw)
            sys.stderr.write('Copied password to clipboard.  '+
                                'Press any key to clear ...\n')
            pol.terminal.wait_for_keypress()
            pol.clipboard.clear()
            return
        found_one = False
        stored = False
        with self._open_safe() as safe:
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter (append-)password: ')):
                if not found_one:
                    found_one = True
                try:
                    container.add(self.args.key, self.args.note, pw)
                    container.save()
                    stored = True
                    break
                except pol.safe.MissingKey:
                    pass
            if not found_one:
                sys.stderr.write('The password did not open any container.\n')
                return -1
            if found_one and not stored:
                sys.stderr.write('No append access to the containers opened '+
                                        'by this password\n')
                return -2
            if self.args.stdout:
                sys.stdout.write(pw)
                sys.stdout.write("\n")
                return
            if self.args.no_copy:
                return
            if not pol.clipboard.available:
                sys.stderr.write('Password stored.  Clipboard access not available.\n')
                sys.stderr.write('Use `pol get\' to show password\n')
                return
            pol.clipboard.copy(pw)
            sys.stderr.write('Copied password to clipboard.  Press any key to clear ...\n')
            pol.terminal.wait_for_keypress()
            pol.clipboard.clear()
            # TODO do rerandomization in parallel

    def cmd_edit(self):
        if self.args.regex:
            try:
                regex = re.compile(self.args.regex, re.I)
            except re.error as e:
                sys.stderr.write("Invalid regex: %s\n" % e.message)
                return -16
        else:
            regex = None
        if not self.args.passwords:
            if self.args.multiple:
                passwords = []
                first = True
                while True:
                    password = getpass.getpass('Enter password: ' if first
                                    else 'Enter next password [done]: ')
                    if first:
                        first = False
                    if not password:
                        break
                    passwords.append(password)
            else:
                passwords = [getpass.getpass('Enter password: ')]
        else:
            passwords = self.args.passwords
        with self._open_safe() as safe:
            # First, generate the file to edit
            editfile = {}
            container_id = 1
            secret_id = 1
            secrets = {}
            containers = {}
            entries = {}
            for password in passwords:
                for container in self._open_containers(safe, password):
                    if not container.has_secrets:
                        continue
                    editfile[container_id] = []
                    containers[container_id] = container
                    entries[container_id] = []
                    for entry in container.list():
                        if regex and not regex.search(entry.key):
                            continue
                        entries[container_id].append(entry)
                        if self.args.secrets:
                            secret = entry.secret
                        else:
                            secrets[secret_id] = entry.secret
                            current_secret_id = secret_id
                            secret_id += 1
                            secret = current_secret_id
                        editfile[container_id].append((
                                    entry.key,
                                    secret,
                                    entry.note))
                    container_id += 1
            if not containers:
                sys.stderr.write('Password(s) did not open any container with secrets\n')
                return -1
            to_edit = pol.editfile.dump(editfile)
            line = None
            # Let the user edit the file.
            while True:
                try:
                    edited = pol.editor.edit(to_edit,
                                filename='pol-edit-file',
                                line=line,
                                syntax='editfile')
                    edited = pol.editfile.remove_errors(edited)
                except pol.editor.NoChanges:
                    sys.stderr.write("No changes.  Aborting.\n")
                    return -21
                try:
                    parsed = pol.editfile.parse(edited, containers.keys(),
                                                    secrets.keys())
                    break
                except pol.editfile.ParseBaseException as e:
                    to_edit = pol.editfile.insert_error(edited, e)
            # Now, apply changes.
            for container_id in parsed:
                container = containers[container_id]
                for i, new_entry in enumerate(parsed[container_id]):
                    key, secret, note = new_entry
                    if isinstance(secret, int):
                        secret = secrets[secret]
                    if i < len(entries[container_id]):
                        entry = entries[container_id][i]
                        entry.key = key
                        entry.note = note
                        entry.secret = secret
                    else:
                        container.add(key, note, secret)
                for i in xrange(len(parsed[container_id]),
                                len(entries[container_id])):
                    entries[container_id][i].remove()

    def cmd_list(self):
        if self.args.regex:
            try:
                regex = re.compile(self.args.regex, re.I)
            except re.error as e:
                sys.stderr.write("Invalid regex: %s\n" % e.message)
                return -16
        else:
            regex = None
        with self._open_safe() as safe:
            found_one = False
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter (list-)password: ')):
                if not found_one:
                    found_one = True
                else:
                    print
                print 'Container @%s' % container.id
                try:
                    got_entry = False
                    for entry in container.list():
                        if regex and not regex.search(entry.key):
                            continue
                        got_entry = True
                        print ' %-20s %s' % (entry.key,
                                    pol.text.escape_cseqs(entry.note)
                                                    if entry.note else '')
                    if not got_entry:
                        if regex:
                            print '  (no matching entries)'
                        else:
                            print '  (empty)'
                except pol.safe.MissingKey:
                    print '  (no list access)'
            if not found_one:
                print ' No containers found'

    def cmd_import(self):
        entries = []
        close_f = False
        # First, read the CSV
        if self.args.path == '-':
            f = sys.stdin
        else:
            if not os.path.exists(self.args.path):
                sys.stderr.write("%s: no such file\n" % self.args.path)
                return -19
            f = open(self.args.path)
            close_f = True
        try:
            reader = csv.reader(f)
            for row in reader:
                if len(row) != 3:
                    sys.stderr.write("%s: row should have exactly 3 entries\n"
                                        % self.args.path)
                    return -20
                entries.append(row)
        finally:
            if close_f:
                f.close()

        # Then, open the pol safe
        with self._open_safe() as safe:
            found_one = False
            the_container = None
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter (append-)password: ')):
                if not found_one:
                    found_one = True
                if container.can_add:
                    the_container = container
                    break
            if not found_one:
                print 'The password did not open any container.'
                return -1
            if not the_container:
                print ('No append access to the containers opened '+
                            'by this password')
                return -2

            # Import the entries
            for entry in entries:
                the_container.add(*entry)
            the_container.save()
            print "%s entries imported" % len(entries)

    def cmd_import_keepass(self):
        # First load keepass db
        kppwd = (self.args.keepass_password if self.args.keepass_password
                        else getpass.getpass('Enter password for KeePass db: '))
        fkeyfile = None
        if self.args.keepass_keyfile:
            fkeyfile = open(self.args.keepass_keyfile)
        try:
            with open(self.args.path) as f:
                groups, entries = pol.importers.keepass.load(f, kppwd, fkeyfile)
        finally:
            if fkeyfile:
                fkeyfile.close()

        # Secondly, find a container
        with self._open_safe() as safe:
            found_one = False
            the_container = None
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                        else getpass.getpass('Enter (append-)password: ')):
                if not found_one:
                    found_one = True
                if container.can_add:
                    the_container = container
                    break
            if not found_one:
                print 'The password did not open any container.'
                return -1
            if not the_container:
                print ('No append access to the containers opened '+
                            'by this password')
                return -2

            # Import the entries
            n_imported = 0
            for entry in entries:
                if not entry['uuid'].int:
                    continue
                notes = []
                n_imported += 1
                if 'notes' in entry and entry['notes']:
                    notes.append(entry['notes'])
                if 'username' in entry and entry['username']:
                    notes.append('user: '+entry['username'])
                if 'url' in entry and entry['url']:
                    notes.append('url: '+entry['url'])
                the_container.add(entry['title'],
                                  '\n'.join(notes),
                                  entry['password'])
            the_container.save()
            print "%s entries imported" % n_imported

    def cmd_import_psafe3(self):
        # First load psafe3 db
        ps3pwd = (self.args.psafe3_password if self.args.psafe3_password
                        else getpass.getpass('Enter password for psafe3 db: '))
        with open(self.args.path) as f:
            header, records = pol.importers.psafe3.load(f, ps3pwd)

        # Secondly, find a container
        with self._open_safe() as safe:
            found_one = False
            the_container = None
            for container in self._open_containers(safe,
                    self.args.password if self.args.password
                            else getpass.getpass('Enter (append-)password: ')):
                if not found_one:
                    found_one = True
                if container.can_add:
                    the_container = container
                    break
            if not found_one:
                print 'The password did not open any container.'
                return -1
            if not the_container:
                print ('No append access to the containers opened '+
                            'by this password')
                return -2

            # Import the records
            for record in records:
                notes = []
                if 'notes' in record and record['notes']:
                    notes.append(record['notes'])
                if 'email-address' in record and record['email-address']:
                    notes.append('email: '+record['email-address'])
                if 'username' in record and record['username']:
                    notes.append('user: '+record['username'])
                if 'url' in record and record['url']:
                    notes.append('url: '+record['url'])
                the_container.add(record['title'],
                                  '\n'.join(notes),
                                  record['password'])
            the_container.save()
            print "%s records imported" % len(records)

    def cmd_speed(self):
        return pol.speed.main(self)

    def cmd_shell(self):
        with demandimport.disabled():
            import readline
        # TODO a more stateful shell would be nice: then we only have to
        #       ask for the password and rerandomize once.
        if not os.path.exists(self.safe_path):
            print "No safe found.  Type `init' to create a new safe."
        while True:
            try:
                line = raw_input('pol> ').strip()
            except EOFError:
                sys.stderr.write("\n")
                break
            except KeyboardInterrupt:
                sys.stderr.write("\nUse C-d to quit.\n")
                continue
            if not line:
                continue
            argv = shlex.split(line)
            try:
                self.parse_args(argv)
            except SystemExit:
                continue
            if self.args.func == self.cmd_shell:
                continue
            self._run_command()

    def cmd_export(self):
        close_f = False
        rows_written = 0
        found_one = False
        try:
            if self.args.path == '-':
                f = sys.stdout
            else:
                if os.path.exists(self.args.path) and not self.args.force:
                    sys.stderr.write("%s exists. Use -f to override.\n"
                                            % self.args.path)
                    return -11
                f = open(self.args.path, 'w')
                close_f = True
            writer = csv.writer(f)
            with self._open_safe() as safe:
                for container in self._open_containers(safe,
                        self.args.password if self.args.password
                                else getpass.getpass('Enter password: ')):
                    found_one = True
                    for entry in container.list():
                        rows_written += 1
                        writer.writerow([entry.key, entry.note, entry.secret])
            if not found_one:
                sys.stderr.write("The password did not open any container.\n")
                return -1
        finally:
            if close_f:
                f.close()
        sys.stderr.write("%s entries exported.\n" % rows_written)

    def cmd_nop(self):
        pass

    def _on_move_append_entries(self, entries):
        """ Called when entries entered by an append-only-password are moved
            into the container. """
        sys.stderr.write("  moved entries into container: %s\n" % (
                pol.humanize.join([entry[0] for entry in entries])))
    def _open_safe(self):
        return pol.safe.open(os.path.expanduser(self.safe_path),
                           nworkers=self.args.workers,
                           use_threads=self.args.threads,
                           progress=Program._RerandProgress())
    def _run_command(self):
        try:
            return self.args.func()
        except pol.safe.SafeNotFoundError:
            sys.stderr.write("%s: no such file.\n" % self.safe_path)
            sys.stderr.write("To create a new safe, run `pol init'.\n")
            return -5
        except pol.safe.SafeLocked:
            sys.stderr.write("%s: locked.\n" % self.safe_path)
            # TODO add a `pol break-lock'
            return -6
        except pol.safe.WrongMagicError:
            sys.stderr.write("%s: not a pol safe.\n" % self.safe_path)
            return -13
        except KeyboardInterrupt:
            sys.stderr.write("\n^C\n")
            return -14
        except Exception:
            self._handle_uncaught_exception()
            return -12
        # TODO gracefully handle SafeFullError

    def _ensure_keyfiles_are_loaded(self):
        """ Ensures self.additional_keys is set to the contents of the
            desired keyfiles. """
        if self.additional_keys or not self.keyfiles:
            return
        self.additional_keys = []
        l.debug('Loading keyfiles ...')
        for keyfile in self.keyfiles:
            l.debug('  %s ...', keyfile)
            with open(keyfile) as f:
                self.additional_keys.append(f.read())

    def _open_containers(self, safe, password):
        self._ensure_keyfiles_are_loaded()
        return safe.open_containers(password,
                        on_move_append_entries=self._on_move_append_entries,
                        additional_keys=self.additional_keys)

    def _handle_uncaught_exception(self):
        sys.stderr.write("\n")
        sys.stderr.write("An unhandled exception occured:\n")
        sys.stderr.write("\n   ")
        sys.stderr.write(traceback.format_exc().replace("\n", "\n   "))
        sys.stderr.write("\n")
        sys.stderr.write("Please report this error:\n")
        sys.stderr.write("\n")
        sys.stderr.write("   https://github.com/bwesterb/pol/issues\n")
        sys.stderr.write("\n")
        sys.stderr.flush()

    class _RerandProgress():
        """ Glue between callbacks of rerandomize and the progressbar. """
        def __init__(self):
            self.progressbar = pol.progressbar.ProgressBar()
            self.started = False
            self.starting_time = None
        def __call__(self, v):
            if self.starting_time is None:
                self.starting_time = time.time()
            if not self.started and time.time() - self.starting_time > 1.0:
                self.started = True
                self.progressbar.start()
            if not self.started:
                return
            self.progressbar(v)
            if v == 1.0:
                self.progressbar.end()

    class _VersionAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_stirng):
            print pol.version.get_version()
            sys.exit()


def entrypoint(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    return Program().main(argv)

if __name__ == '__main__':
    sys.exit(entrypoint())
