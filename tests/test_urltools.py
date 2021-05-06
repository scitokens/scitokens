#!/usr/bin/python
"""
Unit coverage tests for the urltools sub-package
"""

from scitokens.urltools import unquote, normalize_path

import os
import sys
import unittest

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")
if os.path.exists("../src"):
    sys.path.append("../src")

class TestUrltools(unittest.TestCase):
    """
    Test various helper functions copied over from the urltools library.
    """

    def test_unquote(self):
        """
        Run through the logic of the unquote function.
        """
        self.assertEqual(unquote('foo%23bar'), 'foo#bar')
        self.assertEqual(unquote('foo%23bar', ['#']), 'foo%23bar')
        with self.assertRaises(TypeError):
            unquote(None)
        self.assertEqual(unquote(""), "")
        self.assertEqual(unquote("abc123"), "abc123")

    def test_normalize_path(self):
        """
        Run through the logic of the normalize_path function.
        """
        self.assertEqual(normalize_path("//////"), "/")
        self.assertEqual(normalize_path("//"), "/")
        self.assertEqual(normalize_path("//foo/bar//baz"), "/foo/bar/baz")
        self.assertEqual(normalize_path("//foo/bar//baz/"), "/foo/bar/baz/")
        self.assertEqual(normalize_path("//f%20oo/bar"), "/f oo/bar")


if __name__ == '__main__':
    unittest.main()

