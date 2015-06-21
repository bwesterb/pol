""" Some helper functions for the terminal """

import contextlib
import termios
import logging
import getpass
import ctypes
import select
import string
import fcntl
import sys
import os

import demandimport

with demandimport.ignored('simplejson'):
    import zxcvbn

l = logging.getLogger(__name__)

def prompt_yes_or_no(prompt):
    """ Prompts user for a yes or no """
    sys.stderr.write(prompt)
    sys.stderr.write(' y/n')
    sys.stderr.flush()
    ret = None
    while ret is None:
        c = wait_for_keypress()
        if c == 'y':
            ret = True
        if c == 'n':
            ret = False
    print
    return ret

@contextlib.contextmanager
def raw_mode():
    """ Sets the terminal in a raw mode. """
    flags = fcntl.fcntl(0, fcntl.F_GETFL)
    attrs = termios.tcgetattr(0)
    fcntl.fcntl(0, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    new_attrs = list(attrs)
    new_attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK
                        | termios.ISTRIP | termios.INLCR | termios.IGNCR
                        | termios.ICRNL | termios.IXON)
    new_attrs[1] &= ~termios.OPOST
    new_attrs[2] &= ~(termios.CSIZE | termios. PARENB)
    new_attrs[2] |= termios.CS8
    new_attrs[3] &= ~(termios.ECHONL | termios.ECHO | termios.ICANON
                        | termios.ISIG | termios.IEXTEN)
    termios.tcsetattr(0, termios.TCSANOW, new_attrs)
    try:
        yield
    finally:
        termios.tcsetattr(0, termios.TCSAFLUSH, attrs)
        fcntl.fcntl(0, fcntl.F_SETFL, flags)

def purge_stdin():
    while len(select.select([0], [], [], 0.0)[0]):
        os.read(0, 4096)

def wait_for_keypress():
    """ Waits for a single keypress """
    with raw_mode():
        purge_stdin()
        try:
            PyOS_InputHook() # allows GTK to manage clipboard
            ret = sys.stdin.read(1)
        except KeyboardInterrupt:
            ret = 0
    return ret

def zxcvbn_getpass(prompt, prefix='', allow_empty=True):
    """ Similar to getpass.getpass, but shows password strength while typing """
    pw = None
    current = ''
    checked_strength_of = None
    prompt_offset = len(prefix) + len(prompt)
    purge_stdin()
    sys.stderr.write('\033[1G\033[K')
    sys.stderr.write(prefix + prompt)
    sys.stderr.flush()
    interacted = False
    with raw_mode():
        while True:
            if interacted and not pw and checked_strength_of != current:
                strength = zxcvbn.password_strength(current)
                checked_strength_of = current
                text = '%-4s %3sb %s' % (strength['score'] * '*',
                                int(strength['entropy']),
                                strength['crack_time_display'])
                sys.stderr.write('\033[55G\033[K%s\033[%sG' % (
                            text, prompt_offset + 1))
                sys.stderr.flush()
            c = sys.stdin.read(1)
            interacted = True
            if c == '\r' or c == '\n':
                if not current and not pw:
                    if allow_empty:
                        sys.stderr.write('\033[K\n')
                        sys.stderr.flush()
                        return None
                    sys.stderr.write('\033[1G\033[K')
                    new_prompt = prefix+'No password given.  Retry: '
                    sys.stderr.write(new_prompt)
                    prompt_offset = len(new_prompt)
                    sys.stderr.flush()
                    interacted = False
                    continue
                if pw:
                    if pw != current:
                        sys.stderr.write('\033[1G\033[K')
                        new_prompt = prefix+'Passwords did not match.  Retry: '
                        sys.stderr.write(new_prompt)
                        prompt_offset = len(new_prompt)
                        sys.stderr.flush()
                        pw = None
                        current = ''
                        interacted = False
                        continue
                    sys.stderr.write('\033[K\n')
                    sys.stderr.flush()
                    return pw
                pw = current
                current = ''
                sys.stderr.write('\033[1G\033[K')
                new_prompt = prefix + 'Repeat to verify: '
                sys.stderr.write(new_prompt)
                prompt_offset = len(new_prompt)
                sys.stderr.flush()
            elif c in string.printable:
                current += c
            elif c == '\x17': # C-w
                current = current[:current.rfind(' ', 0, -1)+1]
            elif c == '\x15': # C-u
                current = ''
            elif c == '\x7f': # backspace
                current = current[:-1]
            elif c == '\x03': # C-c
                raise KeyboardInterrupt
            else:
                sys.stderr.write('\033[55G\033[Kignored key %r\033[%sG' % (
                                             c, prompt_offset + 1))
                sys.stderr.flush()

def PyOS_InputHook():
    """ Runs PyOS_InputHook, if set.

        Python runs this hook before fgets in raw_input.  Packages like
        gtk set PyOS_InputHook to handle events while the python script
        waits for input on stdin. """
    addr = ctypes.c_void_p.in_dll(ctypes.pythonapi, 'PyOS_InputHook').value
    if not addr:
        return
    ctypes.PYFUNCTYPE(ctypes.c_int)(addr)()
