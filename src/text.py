import unicodedata

def escape_cseqs(s):
    """ Given a (non unicode) string, escapes the (utf-8) control sequences. """
    ret = ''
    if isinstance(s, bytes):
        try:
            us = s.decode('utf-8')
        except UnicodeDecodeError:
            return repr(s)[1:-1]
    else:
        us = s
    for c in us:
        if c == '\n':
            ret += '\\n' 
        elif unicodedata.category(c)[0] != 'C':
            ret += c
        else:
            ret += c.encode('unicode-escape')
    return ret
