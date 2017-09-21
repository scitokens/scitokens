
"""
Useful tools for manipulating pieces of the URL according to the various RFCs.

Original implementation is from the following repo:

   https://github.com/rbaier/python-urltools

and used here with the MIT License, as posted here:

   https://github.com/rbaier/python-urltools/blob/master/LICENSE

Copyright is Roderick Baier, 2014.
The implementations are from git SHA-1 76bf599aeb4cb463df8e38367aa40a7d8ec7d9a1
"""

import posixpath


_HEXTOCHR = dict(('%02x' % i, chr(i)) for i in range(256))


def unquote(text, exceptions=''):
    """Unquote a text but ignore the exceptions.
    >>> unquote('foo%23bar')
    'foo#bar'
    >>> unquote('foo%23bar', ['#'])
    'foo%23bar'
    """
    if not text:
        if text is None:
            raise TypeError('None object cannot be unquoted')
        else:
            return text
    if '%' not in text:
        return text
    split_s = text.split('%')
    res = [split_s[0]]
    for hexchar in split_s[1:]:
        char = _HEXTOCHR.get(hexchar[:2])
        if char and char not in exceptions:
            if len(hexchar) > 2:
                res.append(char + hexchar[2:])
            else:
                res.append(char)
        else:
            res.append('%' + hexchar)
    return ''.join(res)


def normalize_path(path):
    """Normalize path: collapse etc.
    >>> normalize_path('/a/b///c')
    '/a/b/c'
    """
    if path in ['//', '/', '']:
        return '/'
    npath = posixpath.normpath(unquote(path, exceptions='/?+#'))
    if path[-1] == '/' and npath != '/':
        npath += '/'
    while npath.startswith("//"):
        npath = npath[1:]
    return npath
