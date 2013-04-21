""" Cross-platform clipboard support """

import sys
import logging
import subprocess

l = logging.getLogger(__name__)

# First, if we're on Mac, use pbcopy and pbpaste
if sys.platform == 'darwin':
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
    # Then, try GTK
    try:
        import gtk
    except:
        got_gtk = False

    if got_gtk:
        def copy(s):
            cb = gtk.Clipboard()
            cb.set_text(s)
            cb.store()
        def paste():
            return gtk.Clipboard().wait_for_text()
        def clear():
            copy('')
    else:
        # Finally, try Tkinter
        try:
            import Tkinter
            got_tkinter = True
            tk = Tkinter.Tk()
            tk.withdraw()
            tk.destroy()
        except:
            got_tkinter = False
        if got_tkinter:
            available = True
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
        else:
            available = False
            def copy(s):
                raise NotImplementedError
            def paste():
                raise NotImplementedError
            def clear():
                raise NotImplementedError
