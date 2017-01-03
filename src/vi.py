""" curses user interface for pol. """

import os
import logging
import functools

import pol
import pol.safe
import pol.session
import pol.clipboard

import urwid

class PasswordEdit(urwid.Edit):
    """ The edit-box used for entering passwords. """

    def __init__(self, callback):
        super(PasswordEdit, self).__init__('Password: ', mask='*')
        self.callback = callback

    def keypress(self, size, key):
        if key == 'enter':
            self.callback(self.get_edit_text())
        return super(PasswordEdit, self).keypress(size, key)

class EntryWidget(urwid.Columns):
    """ Widget used in the list of entries. """

    def __init__(self, entry, clicked_callback):
        self.entry = entry
        self.clicked_callback = clicked_callback
        super(EntryWidget, self).__init__([
                urwid.SelectableIcon(self.entry.key),
                urwid.Text(self.entry.note if self.entry.note else '')])

    def keypress(self, size, key):
        if key == 'enter':
            self.clicked_callback(self.entry)
        return super(EntryWidget, self).keypress(size, key)

class SessionSearchResultsListWalker(urwid.ListWalker):
    """ Helper for the list of entry widgets. """

    def __init__(self, session, entry_clicked_callback):
        self.session = session
        self.refresh()
        self.focus = 0
        self.entry_clicked_callback = entry_clicked_callback
        super(SessionSearchResultsListWalker, self).__init__()

    def refresh(self):
        self.search_results = []
        for container in self.session.containers:
            try:
                self.search_results.extend(container.list())
            except pol.safe.MissingKey:
                pass

    def __getitem__(self, pos):
        return EntryWidget(self.search_results[pos],
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
        if key == 'ctrl x':
            raise urwid.ExitMainLoop()
        else:
            logging.info("Unknown key %r", key)

    def main(self):
        with pol.safe.open(os.path.expanduser(self.program.safe_path),
                           nworkers=self.program.args.workers,
                           use_threads=self.program.args.threads) as safe:
            self.safe = safe
            self.session = pol.session.Session(safe)

            self.header = urwid.Text("pol {}".format(pol.__version__))
            self.footer = urwid.Text("status")
            self.search_results_walker = SessionSearchResultsListWalker(
                                            self.session,
                                            self.on_entry_clicked)
            self.body = urwid.ListBox(self.search_results_walker)

            self.main_window = urwid.Frame(self.body, self.header, self.footer)
            self.password_edit = PasswordEdit(self.on_password_chosen)
            self.password_dialog = urwid.Overlay(
                    urwid.LineBox(self.password_edit), self.main_window,
                    'center', 20, 'middle', None)
            self.clipboard_dialog_button = urwid.Button("Clear",
                        self.on_clipboard_dialog_closed)
            self.clipboard_dialog = urwid.Overlay(
                    urwid.LineBox(
                        urwid.Pile([urwid.Text("Secret copied to clipboard."),
                        self.clipboard_dialog_button])),
                    self.main_window,
                    'center', 30, 'middle', None)
            self.loop = urwid.MainLoop(self.password_dialog,
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

    def on_clipboard_dialog_closed(self, button):
        pol.clipboard.clear()
        self.show_main_window()

    def on_password_chosen(self, password):
        self.password_edit.set_edit_text('')
        if not self.session.unlock(password):
            return
        self.search_results_walker.refresh()
        self.show_main_window()
        if self._after_password_dialog_callback:
            self._after_password_dialog_callback()

    def show_main_window(self):
        self.loop.widget = self.main_window
    
    def show_password_dialog(self, callback=None):
        self._after_password_dialog_callback = callback
        self.loop.widget = self.password_dialog

    def show_clipboard_dialog(self):
        self.loop.widget = self.clipboard_dialog

def main(program):
    VisualPol(program).main()
