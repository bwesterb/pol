""" Cross-platform clipboard support """

import sys
import logging
import subprocess

l = logging.getLogger(__name__)

# TODO support Linux
# TODO support Windows

if sys.platform == 'darwin':
    # Mac OS X
    available = True
    def copy(s):
        p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        p.stdin.write(s)
        p.stdin.close()
        p.wait()
    def clear():
        copy('')
    def paste():
        return subprocess.check_output(['pbpaste'])
else:
    available = False
    def copy(s):
        raise NotImplementedError
    def clear(s):
        raise NotImplementedError
    def paste(s):
        raise NotImplementedError
