""" parser and dumper for the file format used by `pol edit' """

import cStringIO as StringIO
from pyparsing import ParseException

def insert_error(s, e):
    """ Insert the ParsingException e into s. """
    line_end = s.find('\n', e.loc)
    line_start = s.rfind('\n', 0, e.loc)
    s_head = s[:line_end+1]
    s_tail = s[line_end+1:]
    message = ''
    if line_start + 1 != e.loc:
        message += '#%s^\n' % (' '*(e.loc - line_start - 2))
    message += '# %s\n' % str(e)
    return s_head + message + s_tail

def _grammar():
    from pyparsing import (nums, alphas, lineEnd, stringEnd,
                            OneOrMore, ZeroOrMore, SkipTo, Optional,
                            Word, CharsNotIn, Empty, QuotedString,
                            Suppress, Group, Combine, originalTextFor,
                            ParserElement)

    whiteSpaceChars = ' \t'
    ParserElement.setDefaultWhitespaceChars(whiteSpaceChars)
    word = Empty() + CharsNotIn(whiteSpaceChars + '\n')
    quotedString = QuotedString(quoteChar='"', escChar='\\').setParseAction(
                        lambda s,l,t: t[0].replace("\\n", "\n"))
    number = Word(nums).setParseAction(lambda s,l,t: int(t[0]))
    key = quotedString | word
    secret = Suppress('#') + number | quotedString | word
    note = quotedString | originalTextFor(OneOrMore(word))
    containerKeyword = Suppress('CONTAINER')
    entry = (~containerKeyword + Group(key + secret + Optional(note))
                + Suppress(lineEnd))
    comment = Suppress(lineEnd | '#' + SkipTo(lineEnd))
    line = comment | entry
    containerLine = containerKeyword + number + Suppress(lineEnd)
    containerBlock = ZeroOrMore(comment) + Group(containerLine 
                                                  + Group(OneOrMore(line)))
    multipleContainers = OneOrMore(containerBlock)
    oneContainer = OneOrMore(line).setParseAction(lambda s,l,t: [[None, t]])
    return (multipleContainers | oneContainer) + stringEnd
grammar = _grammar()

def parse(s):
    """ Parses an editfile.  Returns an object of the form:
        
            { container_id: [[key, secret, note], ...] } """
    ret = {}
    for container_id, entries in grammar.parseString(s):
        ret[container_id] = []
        for entry in entries:
            ret[container_id].append((entry[0],
                                      entry[1],
                                      entry[2] if len(entry) >= 3 else None))
    return ret

def quote_string(s):
    for old, new in (('\\', '\\\\'),
                     ('"', '\\"'),
                     ('\n', '\\n')):
        s = s.replace(old, new)
    return '"%s"' % s

def escape_key_or_secret(s):
    if any(c in s for c in (' ', '\t', '\n', '"')):
        return quote_string(s)
    return s
def escape_note(s):
    if any(c in s for c in ('\n', '"')):
        return quote_string(s)
    return s

def dump(d):
    """ Writes an editfile, given by an object of the form

            { container_id: [[key, secret, note], ...] } """
    io = StringIO.StringIO()
    if not d:
        raise ValueError("`d' must not be empty")
    show_container_headers = (len(d) != 1)
    # First step: convert and escape values
    d2 = {}
    for container_id, entries in d.iteritems():
        d2[container_id] = []
        for key, secret, note in entries:
            d2[container_id].append((
                    escape_key_or_secret(key),
                    '#'+str(secret) if isinstance(secret, int)
                            else escape_key_or_secret(secret),
                    escape_note(note) if note else None))
    # Now, determine alignment
    max_key_len = max(max(len(key) for key, secret, note in entries)
                            for entries in d2.itervalues())
    max_secret_len = max(max(len(secret) for key, secret, note in entries)
                            for entries in d2.itervalues())
    first_container = True
    # And dump!
    for container_id, entries in d2.iteritems():
        if first_container:
            first_container = False
        else:
            io.write("\n")
        if show_container_headers:
            io.write("CONTAINER %s\n" % container_id)
        for key, secret, note in entries:
            io.write(key.ljust(max_key_len))
            io.write(' ')
            io.write(secret.ljust(max_secret_len))
            if note:
                io.write(' ')
                io.write(note)
            io.write('\n')
    return io.getvalue()
