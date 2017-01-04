""" curses user interface for pol. """

import os
import logging
import functools

import pol
import pol.safe
import pol.session
import pol.clipboard

import urwid
import fuzzywuzzy.fuzz

l = logging.getLogger(__name__)

PALETTE = [
        ('header', 'white', 'dark blue'),
        ('status', 'white', 'dark blue'),
        ('query', 'white,bold', 'dark magenta'),
        ]

class PasswordEdit(urwid.Edit):
    """ The edit-box used for entering passwords. """

    def __init__(self, callback):
        super(PasswordEdit, self).__init__('Password: ', mask='*')
        self.callback = callback

    def keypress(self, size, key):
        if key == 'enter':
            self.callback(self.get_edit_text())
            return
        return super(PasswordEdit, self).keypress(size, key)

class EntryWidget(urwid.Columns):
    """ Widget used in the list of entries. """

    def __init__(self, entry, score, clicked_callback):
        self.entry = entry
        self.score = score
        self.clicked_callback = clicked_callback
        super(EntryWidget, self).__init__([
                urwid.SelectableIcon(self.entry.key),
                # urwid.Text(str(self.score)),
                urwid.Text(self.entry.note if self.entry.note else '')])

    def keypress(self, size, key):
        if key == 'enter':
            self.clicked_callback(self.entry)
            return
        return super(EntryWidget, self).keypress(size, key)

class SessionSearchResultsListWalker(urwid.ListWalker):
    """ Helper for the list of entry widgets. """

    def __init__(self, session, entry_clicked_callback):
        self.session = session
        self.refresh()
        self.focus = 0
        self.query = ''
        self.entry_clicked_callback = entry_clicked_callback
        super(SessionSearchResultsListWalker, self).__init__()

    def set_query(self, query):
        self.query = query
        self.refresh()

    def refresh(self):
        # TODO optimize
        self.search_results = sorted(filter(lambda x: x[0], (
                (entry, fuzzywuzzy.fuzz.WRatio(self.query, entry.key)
                        if self.query else 0)
                    for entry in self.session.entries)),
                        key=lambda x: (100 - x[1], x[0].key))

    def __getitem__(self, pos):
        return EntryWidget(self.search_results[pos][0],
                    self.search_results[pos][1],
                    self.entry_clicked_callback)

    def next_position(self, pos):
        if pos >= len(self.search_results):
            raise IndexError
        return pos + 1

    def prev_position(self, pos):
        if pos <= 0:
            raise IndexError
        return pos - 1

    def set_focus(self, pos):
        if pos < 0 or pos >= len(self.search_results):
            raise IndexError
        self.focus = pos


class VisualPol(object):
    """ Visual ncurses interface to pol. """

    def __init__(self, program):
        self.program = program

        # Called after the password dialog has been used and the
        # containers have been opened.
        self._after_password_dialog_callback = None

    def unhandled_input(self, key):
        if key == 'ctrl p':
            if self.loop.widget is self.main_window:
                self.show_password_dialog()
        elif key == 'ctrl l':
            self.loop.draw_screen()
        elif key == 'ctrl x':
            raise urwid.ExitMainLoop()
        elif not self.query.keypress((0,), key):
            self.show_query()
        else:
            self.info("Unknown key %r.  Press ctrl-x to exit.", key)

    def info(self, text, *args):
        l.info(text, *args)
        fmt_text = text % args
        self.status.set_text(fmt_text)

    def main(self):
        with pol.safe.open(os.path.expanduser(self.program.safe_path),
                           nworkers=self.program.args.workers,
                           use_threads=self.program.args.threads) as safe:
            self.safe = safe
            self.session = pol.session.Session(safe)

            # Header
            self.header = urwid.AttrWrap(urwid.Text(
                "pol {}".format(pol.__version__)), 'header')

            # Footer
            self.status = urwid.Text("")
            self.wrappedStatus = urwid.AttrWrap(self.status, 'status')
            self.query = urwid.Edit('/')
            self.wrappedQuery = urwid.AttrWrap(self.query, 'query')
            urwid.connect_signal(self.query, 'change', self.on_query_changed)

            # List
            self.search_results_walker = SessionSearchResultsListWalker(
                                            self.session,
                                            self.on_entry_clicked)
            self.body = urwid.ListBox(self.search_results_walker)

            # Main window
            self.main_window = urwid.Frame(self.body, self.header,
                    self.wrappedStatus)

            # Password dialog
            self.password_edit = PasswordEdit(self.on_password_chosen)
            self.password_dialog = urwid.Overlay(
                    urwid.LineBox(self.password_edit), self.main_window,
                    'center', 20, 'middle', None)

            # Clipboard dialog
            self.clipboard_dialog_button = urwid.Button("Clear",
                        self.on_clipboard_dialog_closed)
            self.clipboard_dialog = urwid.Overlay(
                    urwid.LineBox(
                        urwid.Pile([urwid.Text("Secret copied to clipboard."),
                        self.clipboard_dialog_button])),
                    self.main_window,
                    'center', 30, 'middle', None)

            # Loop
            self.loop = urwid.MainLoop(self.password_dialog, PALETTE,
                               unhandled_input=self.unhandled_input)
            self.loop.run()

    def on_entry_clicked(self, entry):
        try:
            pol.clipboard.copy(entry.secret)
        except pol.safe.MissingKey:
            self.show_password_dialog(
                    functools.partial(self.on_entry_clicked, entry))
            return
        self.show_clipboard_dialog()

    def on_query_changed(self, widget, new_text):
        self.search_results_walker.set_query(new_text)
        if not new_text:
            self.hide_query(reset_query=False, reset_focus=False)
        self.body._invalidate()

    def on_clipboard_dialog_closed(self, button):
        pol.clipboard.clear()
        self.info("Clipboard cleared")
        self.hide_query()
        self.show_main_window()

    def on_password_chosen(self, password):
        self.password_edit.set_edit_text('')
        if not self.session.unlock(password):
            self.info("Password did not unlock any container")
            return
        self.info('')
        self.search_results_walker.refresh()
        self.show_main_window()
        if self._after_password_dialog_callback:
            self._after_password_dialog_callback()
        else:
            self.hide_query()

    def show_main_window(self):
        self.loop.widget = self.main_window

    def show_query(self):
        self.main_window.footer = self.wrappedQuery

    def hide_query(self, reset_query=True, reset_focus=True):
        if self.query.edit_text and reset_query:
            self.query.set_edit_text('')
        if reset_focus:
            self.body.set_focus(0)
        self.main_window.set_footer(self.wrappedStatus)
    
    def show_password_dialog(self, callback=None):
        self._after_password_dialog_callback = callback
        self.loop.widget = self.password_dialog

    def show_clipboard_dialog(self):
        self.loop.widget = self.clipboard_dialog

def main(program):
    VisualPol(program).main()
