def join(s):
    if len(s) <= 1:
        return s[0]
    return ', '.join(s[:-1]) + ' and ' + s[-1]
