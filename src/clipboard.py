""" Cross-platform clipboard support """

import sys
import logging
import subprocess

l = logging.getLogger(__name__)

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
    import Tkinter
    def clear():
        tk = Tkinter.Tk()
        tk.withdraw()
        tk.clipboard_clear()
        tk.destroy()
    def copy(s):
        tk = Tkinter.Tk()
        tk.withdraw()
        tk.clipboard_clear()
        tk.clipboard_append(s)
        tk.destroy()
    def paste():
        tk = Tkinter.Tk()
        tk.withdraw()
        ret = tk.clipboard_get()
        tk.destroy()
        return ret
