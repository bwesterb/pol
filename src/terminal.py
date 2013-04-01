""" Some helper functions for the terminal """

import termios
import select
import fcntl
import sys
import os

def wait_for_keypress():
    """ Waits for a single keypress """
    # First, set up stdin
    flags = fcntl.fcntl(0, fcntl.F_GETFL)
    attrs = termios.tcgetattr(0)
    fcntl.fcntl(0, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    new_attrs = list(attrs)
    new_attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK
                        | termios.ISTRIP | termios.INLCR | termios. IGNCR
                        | termios.ICRNL | termios.IXON)
    new_attrs[1] &= ~termios.OPOST
    new_attrs[2] &= ~(termios.CSIZE | termios. PARENB)
    new_attrs[2] |= termios.CS8
    new_attrs[3] &= ~(termios.ECHONL | termios.ECHO | termios.ICANON
                        | termios.ISIG | termios.IEXTEN)
    termios.tcsetattr(0, termios.TCSANOW, new_attrs)
    # Now, purge stin
    while len(select.select([0], [], [], 0.0)[0]):
        os.read(0, 4096)
    # Finally, read a single keystroke
    try:
        ret = sys.stdin.read(1) # returns a single character
    except KeyboardInterrupt: 
        ret = 0
    finally:
        termios.tcsetattr(0, termios.TCSAFLUSH, attrs)
        fcntl.fcntl(0, fcntl.F_SETFL, flags)
    return ret
