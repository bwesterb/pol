#!/usr/bin/env python

""" Entry point of the console application.

    Contains the argument parser and CLI interaction. """

import threading
import argparse
import logging
import os.path
import getpass
import pprint
import sys

import pol.safe
import pol.passgen
import pol.terminal
import pol.clipboard
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

        p_generate = subparsers.add_parser('generate',
                    help='Generates and stores a password')
        p_generate.add_argument('key')
        p_generate.add_argument('--note', '-n')
        p_generate.set_defaults(func=self.cmd_generate)

        p_paste = subparsers.add_parser('paste',
                    help='Stores a secret from the clipboard')
        p_paste.add_argument('key')
        p_paste.add_argument('--note', '-n')
        p_paste.set_defaults(func=self.cmd_paste)

        p_copy = subparsers.add_parser('copy',
                    help='Copies a password to the clipboard')
        p_copy.add_argument('key')
        p_copy.set_defaults(func=self.cmd_copy)

        p_touch = subparsers.add_parser('touch',
                    help='Rerandomizes blocks')
        p_touch.set_defaults(func=self.cmd_touch)

        p_raw = subparsers.add_parser('raw',
                    help='Shows raw data of safe')
        p_raw.add_argument('--blocks', '-b', action='store_true', dest='blocks',
                    help='Also print blocks')
        p_raw.set_defaults(func=self.cmd_raw)

        p_import_psafe3 = subparsers.add_parser('import-psafe3',
                    help='Imports entries from a psafe3 db')
        p_import_psafe3.add_argument('path',
                    help='Path to psafe3 database')
        p_import_psafe3.set_defaults(func=self.cmd_import_psafe3)

        self.args = parser.parse_args(argv)

    def main(self, argv):
        # Parse arguments
        self.parse_args(argv)

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
        # TODO do not override existing safe
        print "You are about to create a new safe.  A can have up to six"
        print "separate containers to store your secrets.  A container is"
        print "accessed by one of its passwords.  Without one of its passwords,"
        print "you cannot prove the existence of a container."
        print
        first = True
        second = False
        pws = []
        for i in xrange(1, 7):
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
            if first:
                masterpw = getpass.getpass('    Enter master-password: ')
            else:
                masterpw = getpass.getpass('    Enter master-password [stop]: ')
                if not masterpw:
                    break
            if first:
                print
                print "  A container can have a list-password.  With this password you can"
                print "  list and add entries.  You cannot see the secrets of the existing"
                print "  entries.  Leave blank if you do not want a list-password."
                print
            listpw = getpass.getpass('    Enter list-password [no list-password]: ')
            if first:
                print
                print "  A container can have an append-password.  With this password you"
                print "  can only add entries.  You cannot see the existing entries."
                print "  Leave blank if you do not want an append-passowrd."
                print
            appendpw = getpass.getpass('    Enter append-password [no append-password]: ')
            if second:
                second = False
            if first:
                first = False
                second = True
            pws.append((masterpw if masterpw else None,
                        listpw if listpw else None,
                        appendpw if appendpw else None))
        print
        if not self.args.precomputed_gp:
            print 'Generating group parameters for this safe. This can take a while ...'
        # TODO add sanity checks for rerand_bits and nworkers
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
        safe = pol.safe.Safe.generate(nworkers=self.args.workers,
                                      gp_bits=self.args.rerand_bits,
                                      progress=progress,
                                      precomputed_gp=self.args.precomputed_gp,
                                      use_threads=self.args.threads)
        for i, mlapw in enumerate(pws):
            mpw, lpw, apw = mlapw
            print '  allocating container #%s ...' % (i+1)
            c = safe.new_container(mpw, lpw, apw)
        print '  trashing freespace ...'
        safe.trash_freespace()
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)
    
    def cmd_touch(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        self._rerandomize(safe)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)

    def cmd_raw(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        d = safe.data
        if not self.args.blocks:
            del d['blocks']
        pprint.pprint(d)

    def cmd_copy(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        found_one = False
        entries = []
        for container in safe.open_containers(
                getpass.getpass('Enter password: ')):
            if not found_one:
                found_one = True
            try:
                for entry in container.get(self.args.key):
                    if len(entry) == 3:
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
        if len(entries) == 1:
            entry = entries[0][1]
            print ' note: %s' % repr(entry[1])
            print 'Copied secret to clipboard.  Press any key to clear ...'
            pol.clipboard.copy(entry[2])
            pol.terminal.wait_for_keypress()
            pol.clipboard.clear()
            return
        print '%s entries found.' % len(entries)
        print
        first = True
        for i, tmp in enumerate(entries):
            if first:
                first = False
            else:
                print
            container, entry = tmp
            print 'Entry #%s from container @%s' % (i+1, container.id)
            print ' note: %s' % repr(entry[1])
            print 'Copied secret to clipboard.  Press any key to clear ...'
            pol.clipboard.copy(entry[2])
            pol.terminal.wait_for_keypress()
            pol.clipboard.clear()
    def cmd_paste(self):
        pw = pol.clipboard.paste()
        if not pw:
            print 'Clipboard is empty'
            return -3
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        found_one = False
        stored = False
        for container in safe.open_containers(
                getpass.getpass('Enter (append-)password: ')):
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
        pol.clipboard.clear()
        self._rerandomize(safe)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)

    def cmd_generate(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        pw = pol.passgen.generate_password()
        found_one = False
        stored = False
        for container in safe.open_containers(
                getpass.getpass('Enter (append-)password: ')):
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
        pol.clipboard.copy(pw)

        finished = threading.Event()
        def finish_up():
            self._rerandomize(safe)
            with open(os.path.expanduser(self.args.safe), 'w') as f:
                safe.store(f)
            finished.set()
        threading.Thread(target=finish_up).start()
        print 'Copied password to clipboard.  Press any key to clear ...'
        pol.terminal.wait_for_keypress()
        pol.clipboard.clear()
        finished.wait()

    def cmd_list(self):
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        found_one = False
        for container in safe.open_containers(
                getpass.getpass('Enter (list-)password: ')):
            if not found_one:
                found_one = True
            else:
                print
            print 'Container @%s' % container.id
            try:
                got_entry = False
                for key, note in container.list():
                    got_entry = True
                    print ' %-20s %s' % (key, repr(note) if note else '')
                if not got_entry:
                    print '  (empty)'
            except pol.safe.MissingKey:
                print '  (no list access)'
        if not found_one:
            print ' No containers found'

    def cmd_import_psafe3(self):
        # First load psafe3 db
        import pol.importers.psafe3
        ps3pwd = getpass.getpass('Enter password for psafe3 db: ')
        with open(self.args.path) as f:
            header, records = pol.importers.psafe3.load(f, ps3pwd)

        # Secondly, find a container
        with open(os.path.expanduser(self.args.safe)) as f:
            safe = pol.safe.Safe.load(f)
        found_one = False
        the_container = None
        for container in safe.open_containers(
                getpass.getpass('Enter (append-)password: ')):
            if not found_one:
                found_one = True
            if container.can_add:
                the_container = container
                break
        if not found_one:
            print 'The password did not open any container.'
            return -1
        if not the_container:
            print 'No append access to the containers opened by this password'
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

        self._rerandomize(safe)
        with open(os.path.expanduser(self.args.safe), 'w') as f:
            safe.store(f)

    def _rerandomize(self, safe):
        progressbar = pol.progressbar.ProgressBar()
        progressbar.start()
        def progress(v):
            progressbar(v)
            if v == 1.0:
                progressbar.end()
        safe.rerandomize(nworkers=self.args.workers,
                         use_threads=self.args.threads,
                         progress=progress)


def entrypoint(argv):
    return Program().main(argv)

if __name__ == '__main__':
    sys.exit(entrypoint(sys.argv[1:]))
