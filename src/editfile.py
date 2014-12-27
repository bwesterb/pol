""" parser and dumper for the file format used by `pol edit' """

import re
import cStringIO as StringIO
from pyparsing import ParseException, ParseBaseException

# TODO add unittests

def insert_error(s, e):
    """ Insert the ParseException e into s. """
    message = ''
    if e.loc == 0:
        s_head = ''
        s_tail = s
    else:
        line_end = s.find('\n', e.loc)
        line_start = s.rfind('\n', 0, e.loc)
        s_head = s[:line_end+1]
        s_tail = s[line_end+1:]
        if line_start + 1 != e.loc:
            message += '#%s^\n' % (' '*(e.loc - line_start - 2))
    message += '# ERROR %s\n' % str(e)
    return s_head + message + s_tail

def remove_errors(s):
    """ Removes error messages inserted by `insert_error' from s """
    # Removes error messages at the start of the string.
    while s.startswith('# ERROR'):
        s = s[s.find('\n')+1:]
    while True:
        # Find an error message in the middle of the string
        index = s.find('\n# ERROR')
        if index == -1:
            break
        # Check if the previous line is a column indicator, like this:
        #                                        ^
        # and remove it.
        pIndex = s.rfind('\n', 0, index)
        if pIndex != -1 and re.match('^# *\\^', s[pIndex+1:index]):
            s = s[:pIndex] + s[index:]
            continue
        # Remove the error message line.
        nIndex = s.find('\n', index+1)
        if nIndex == -1:
            s = s[:index+1]
        else:
            s = s[:index+1] + s[nIndex+1:]
    return s

def create_grammar(container_ids, secret_ids):
    """ Create the grammar for the editfile """
    from pyparsing import (nums, alphas, lineEnd, stringEnd,
                            OneOrMore, ZeroOrMore, SkipTo, Optional, And,
                            Word, CharsNotIn, Empty, QuotedString, Literal,
                            Suppress, Group, Combine, originalTextFor, Forward,
                            ParserElement)
    # Read from bottom to top
    whiteSpaceChars = ' \t'
    ParserElement.setDefaultWhitespaceChars(whiteSpaceChars)
    word = Empty() + CharsNotIn(whiteSpaceChars + '\n')
    quotedString = QuotedString(quoteChar='"', escChar='\\').setParseAction(
                        # NOTE the second replace is a work-around for
                        #      pyparsing bug #68.
                        #       https://sourceforge.net/p/pyparsing/bugs/68/
                        lambda s,l,t: t[0].replace("\\n", "\n").replace(
                                                   "\\\\", "\\"))
    def secretIdNumberParseAction(s, loc, tokens):
        v = int(tokens[0])
        if not v in secret_ids:
            raise ParseException(s, loc, "Not a valid secret id")
        return v
    secretIdNumber = Word(nums).setParseAction(secretIdNumberParseAction)
    def containerIdParseAction(s, loc, tokens):
        v = int(tokens[0])
        if not v in container_ids:
            raise ParseException(s, loc, "Not a valid container id")
        return v
    containerId = Word(nums).setParseAction(containerIdParseAction)
    key = quotedString | word
    secretString = ~Literal('#') + (quotedString | word)
    secretId = Suppress('#') + secretIdNumber
    secret = secretString | secretId
    note = quotedString | originalTextFor(OneOrMore(word))
    containerKeyword = Suppress('CONTAINER')
    entry = (~containerKeyword + Group(key - secret - Optional(note))
                - Suppress(lineEnd))
    comment = Suppress(lineEnd | '#' + SkipTo(lineEnd))
    line = comment | entry
    containerLine = containerKeyword + containerId + comment
    # Instead of the following recursive grammar, we could have simply used
    #
    #     containerBlock = ZeroOrMore(comment) + Group(containerLine
    #                                                + Group(OneOrMore(line)))
    #     multipleContainers = OneOrMore(containerBlock)
    #
    # but then any parsing error in line will result in a "expected stringEnd"
    # or "expected CONTAINER".
    _multipleContainers_head = Forward()
    _multipleContainers_body = Forward()
    _multipleContainers_head << (stringEnd | comment + _multipleContainers_head
                    | containerLine + _multipleContainers_body)
    _multipleContainers_body << (stringEnd
                    | (containerLine | line) + _multipleContainers_body)
    _multipleContainers_entry = And([entry])
    multipleContainers = And([_multipleContainers_head]) # TODO ibidem below
    containerLine.setParseAction(lambda s,l,t: [[None, t[0]]])
    def multipleContainersParseAction(s, loc, tokens):
        curEntries = []
        curId = None
        ret = []
        for t in tuple(tokens) + ((None, None),):
            if t[0] is not None:
                assert curId is not None
                curEntries.append(t)
                continue
            if curId is not None:
                ret.append([curId, curEntries])
            curId = t[1]
            curEntries = []
        return ret
    multipleContainers.setParseAction(multipleContainersParseAction)
    oneContainer = ZeroOrMore(line) + stringEnd
    oneContainer.setParseAction(lambda s,l,t: [[None, t]])
    grammar = multipleContainers | oneContainer
    return grammar

def parse(s, container_ids, secret_ids):
    """ Parses an editfile.  Returns an object of the form:

            { container_id: [[key, secret, note], ...] } """
    ret = {}
    grammar = create_grammar(container_ids, secret_ids)
    for container_id, entries in grammar.parseString(s):
        if container_id is None:
            if len(container_ids) != 1:
                raise ParseException(s, msg='Expected multiple containers')
            container_id = container_ids[0]
        if container_id in ret:
            raise ParseException(s, msg='Duplicate container_id %s'
                                            % container_id)
        ret[container_id] = []
        for entry in entries:
            ret[container_id].append((entry[0],
                                      entry[1],
                                      entry[2] if len(entry) >= 3 else None))
    for container_id in container_ids:
        if container_id not in ret:
            raise ParseException(s, msg='Missing container %s' % container_id)
    return ret

def quote_string(s):
    for old, new in (('\\', '\\\\'),
                     ('"', '\\"'),
                     ('\n', '\\n')):
        s = s.replace(old, new)
    return '"%s"' % s

def escape_key(s):
    if s.startswith('CONTAINER') or s.startswith('#'):
        return quote_string(s)
    return escape_key_or_secret(s)
def escape_secret(s):
    if s.startswith('#'):
        return quote_string(s)
    return escape_key_or_secret(s)
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
                    escape_key(key),
                    '#'+str(secret) if isinstance(secret, int)
                            else escape_secret(secret),
                    escape_note(note) if note else None))
    # Now, determine alignment
    max_key_len = max(max(len(key) for key, secret, note in entries)
                                if entries else 1
                            for entries in d2.itervalues())
    max_secret_len = max(max(len(secret) for key, secret, note in entries)
                                if entries else 1
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
