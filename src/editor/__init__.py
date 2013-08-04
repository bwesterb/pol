""" Code to launch an external editor. """

import os
import shutil
import logging
import os.path
import tempfile
import subprocess

import pkg_resources

l = logging.getLogger(__name__)

class EditorException(OSError):
    pass

class NoChanges(EditorException):
    pass

def get_editor():
    """ Returns the configured editor. """
    for var in ('POL_EDITOR', 'EDITOR'):
        if var in os.environ:
            return os.environ[var]
    return 'vi'

# TODO can we prevent creating a file with the entries?
def edit(s, filename=None, line=None, syntax=None):
    """ Opens an external editor for the string s. """
    if not filename:
        filename = 'file'
    dir_path = tempfile.mkdtemp()
    try:
        file_path = os.path.join(dir_path, filename)
        with open(file_path, 'w') as f:
            f.write(s)
        old_mtime = os.path.getmtime(file_path)
        editor = get_editor()
        args = [editor, file_path]
        # TODO make this more robust
        if editor in ('vi', 'vim') and line:
            args.append('+%s' % line)
        if syntax and editor == 'vim':
            args.append('-S')
            args.append(pkg_resources.resource_filename(
                                __name__, '%s.vim' % syntax))
        l.debug("Calling %s" % str(args))
        if subprocess.call(args) != 0:
            raise EditorException
        with open(file_path, 'r') as f:
            s2 = f.read()
        if s == s2:
            raise NoChanges
        return s2
    finally:
        shutil.rmtree(dir_path)
