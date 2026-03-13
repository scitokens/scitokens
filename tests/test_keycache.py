"""
Test the keycache
"""

import os, stat
import sys
import tempfile
import shutil
import unittest
import pytest       # to skip tests
from unittest import mock
from scitokens.utils.keycache import KeyCache
from scitokens.utils.errors import UnableToCreateCache
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Python 3 vs. Python 2
try:
    from urllib.error import URLError
except ImportError:
    from urllib2 import URLError

import create_webserver


class TestKeyCache(unittest.TestCase):
    """
    Test the creation of a simple SciToken
    """

    def setUp(self):


        # Force the keycache to create a cache in a new directory
        self.tmp_dir = tempfile.mkdtemp()
        self.old_xdg = os.environ.get('XDG_CACHE_HOME', None)
        os.environ['XDG_CACHE_HOME'] = self.tmp_dir
        # Clear the cache
        self.keycache = KeyCache()

        # make sure it made the directory where I wanted it
        self.assertTrue(self.keycache.cache_location.startswith(self.tmp_dir))
        self.assertTrue(os.path.exists(self.keycache.cache_location))


    def tearDown(self):
        shutil.rmtree(self.tmp_dir)
        if self.old_xdg:
            os.environ['XDG_CACHE_HOME'] = self.old_xdg
        # Clean up, delete everything

    @mock.patch("os.makedirs", side_effect=OSError)
    @mock.patch.dict("os.environ")
    def test_cannot_make_cache(self, _):
        """
        Test when the keycache shouldn't be able to make the cache
        """
        os.environ['XDG_CACHE_HOME'] = "/does/not/exists"

        # Make keycache doesn't fail when unable to make cache file
        try:
            keycache = KeyCache()
            del keycache
        except Exception as e:
            self.fail("Creating a cache threw an error, when it should be a silent failure: {}".format(e))


    @unittest.skipIf(sys.platform.startswith("win"), "Test doesn't work on Windows")
    @unittest.skipIf(not sys.platform.startswith("win") and os.getuid() == 0, "Test doesn't work when root")
    def test_cannot_make_cache_permission_denied(self):
        """
        Test when the keycache shouldn't be able to make the cache due to access privilege
        """
        os.environ['XDG_CACHE_HOME'] = self.tmp_dir

        # Limiting access privilege to read-only for the $XDG_CACHE_HOME
        os.chmod(
            self.tmp_dir,
            stat.S_IRUSR |  # Read for user
            stat.S_IRGRP |  # Read for group
            stat.S_IROTH    # Read for other
        )

        # Create a pem encoded public key
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Make sure creating a cache and writing/reading to it does not fail
        try:
            keycache = KeyCache()
            self.keycache.addkeyinfo("https://doesnotexists.edu/", "blahstuff", public_key, cache_timer=60)
            del keycache
        except Exception as e:
            self.fail("Creating a cache and writing/reading to it failed: {}".format(e))

        # Revert the access privilege alteration for the $XDG_CACHE_HOME
        os.chmod(
            self.tmp_dir,
            stat.S_IRWXU |  # Read, write, and execute for user
            stat.S_IRWXG |  # Read, write, and execute for group
            stat.S_IRWXO    # Read, write, and execute for other
        )

    def test_empty(self):
        """
        Test when the keycache should be empty
        """
        # Stand up an HTTP server
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_numbers = private_key.public_key().public_numbers()
        test_id = "thisisatestid"
        server_address = create_webserver.start_server(public_numbers.n, public_numbers.e, test_id)
        print(server_address)
        # Now try to get the public key from the server
        pubkey_from_keycache = self.keycache.getkeyinfo("http://localhost:{}/".format(server_address[1]),
                                 test_id,
                                 insecure=True)

        # Now compare the 2 public keys
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pubkey_pem_from_keycache = pubkey_from_keycache.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.assertEqual(public_pem, pubkey_pem_from_keycache)

        create_webserver.shutdown_server()

    def test_populated(self):
        """
        Test when there should be some entries populated in the sqllite DB
        """
        # Create a pem encoded public key
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.keycache.addkeyinfo("https://doesnotexists.edu/", "blahstuff", public_key, cache_timer=60)

        # Now extract the just inserted key
        pubkey = self.keycache.getkeyinfo("https://doesnotexists.edu/", "blahstuff")

        public_pem2 = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.assertEqual(public_pem, public_pem2)

        # Make sure it errors with urlerror when it should not exist
        with self.assertRaises(URLError):
            self.keycache.getkeyinfo("https://doesnotexists.edu/", "asdf")

    @unittest.skipIf(sys.platform.startswith("win"), "Test doesn't work on Windows")
    @unittest.skipIf(not sys.platform.startswith("win") and os.getuid() == 0, "Test doesn't work when root")
    def test_immutable_cache(self):
        """
        Test when there should be some entries populated in the sqllite DB, but the keycache is immutable
        """
        # Create a pem encoded public key
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Populate the keycache
        self.keycache.addkeyinfo("https://doesnotexists.edu/", "blahstuff", public_key, cache_timer=60)

        # Make the keycache immutable
        # Limiting access privilege to read-only for the $XDG_CACHE_HOME
        os.chmod(
            self.keycache.cache_location,
            stat.S_IRUSR |  # Read for user
            stat.S_IRGRP |  # Read for group
            stat.S_IROTH    # Read for other
        )

        # Now extract the just inserted key
        pubkey = self.keycache.getkeyinfo("https://doesnotexists.edu/", "blahstuff")
        self.assertIsNotNone(pubkey, "The key should be in the cache")

        # Now try to insert a new key, it should not fail, but it also should not be writable
        self.keycache.addkeyinfo("https://anotherdoesnotexist.edu/", "another", public_key, cache_timer=60)
        # Getting the cache now should fail, but with a URL error, not a reading from the keycache error
        # A URL error because the above addkeyinfo didn't actually add the key to the cache
        # so the keycache tried to download the key from the web, which failed
        with self.assertRaises(URLError):
            another_pubkey = self.keycache.getkeyinfo("https://anotherdoesnotexist.edu/", "another")

        # Revert the access privilege alteration for the $XDG_CACHE_HOME
        os.chmod(
            self.keycache.cache_location,
            stat.S_IRWXU |  # Read, write, and execute for user
            stat.S_IRWXG |  # Read, write, and execute for group
            stat.S_IRWXO    # Read, write, and execute for other
        )

    def test_cache_timer(self):
        """
        Test if the cache max-age is retrieved from the HTTPS resource
        """
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_numbers = private_key.public_key().public_numbers()
        test_id = "thisisatestid"
        server_address = create_webserver.start_server(public_numbers.n, public_numbers.e, test_id)
        print(server_address)

        _, cache_timer = self.keycache._get_issuer_publickey("http://localhost:{}/".format(server_address[1]),
                                            key_id=test_id,
                                            insecure=True)

        self.assertEqual(cache_timer, 345600)
        create_webserver.shutdown_server()

    def test_cache_update_time(self):
        """
        Test if the cache next_update works
        """
        # Create a pem encoded public key
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.keycache.addkeyinfo("https://doesnotexists.edu/", "blahstuff", public_key, cache_timer=60, next_update=-1)

        # Even though the cache is still valid, the next update is triggered
        # We should still get the key, even though the next update fails
        # (invalid url)
        pubkey = self.keycache.getkeyinfo("https://doesnotexists.edu/", "blahstuff")

        public_pem2 = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.assertEqual(public_pem, public_pem2)

    def test_cache_update_trigger(self):
        """
        Test when the next_update triggers and goes to the webserver
        """
        # Stand up an HTTP server
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_numbers = private_key.public_key().public_numbers()
        test_id = "thisisatestid"
        server_address = create_webserver.start_server(public_numbers.n, public_numbers.e, test_id)
        print(server_address)

        # Create a pem encoded public key, just to insert, want to make sure
        # it downloads from the server
        tmp_private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = tmp_private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Now try to get the public key from the server
        self.keycache.addkeyinfo("http://localhost:{}/".format(server_address[1]),
                                 test_id,
                                 public_key,
                                 cache_timer=60,
                                 next_update=-1)

        # Next update should trigger now
        pubkey_from_keycache = self.keycache.getkeyinfo("http://localhost:{}/".format(server_address[1]),
                                 test_id,
                                 insecure=True)

        # Now compare the 2 public keys
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pubkey_pem_from_keycache = pubkey_from_keycache.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.assertEqual(public_pem, pubkey_pem_from_keycache)

        create_webserver.shutdown_server()


import sqlite3

class TestKeyCacheSQLInjection(unittest.TestCase):
    """
    Regression tests to verify that SQL injection via issuer/key_id is not possible.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.old_xdg = os.environ.get('XDG_CACHE_HOME', None)
        os.environ['XDG_CACHE_HOME'] = self.tmp_dir
        self.keycache = KeyCache()

        # Generate a test key pair
        self.private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)
        if self.old_xdg:
            os.environ['XDG_CACHE_HOME'] = self.old_xdg

    def _count_rows(self):
        conn = sqlite3.connect(self.keycache.cache_location)
        curs = conn.cursor()
        curs.execute("SELECT COUNT(*) FROM keycache")
        count = curs.fetchone()[0]
        conn.close()
        return count

    def test_injection_in_issuer_does_not_delete_other_rows(self):
        """
        With the old .format() pattern, an issuer like "x' OR '1'='1" in a
        DELETE would wipe every row. Parameterized queries treat it as a
        literal value, so no rows other than the exact match are affected.
        """
        # Insert a legitimate row
        self.keycache.addkeyinfo("https://legit.example.com/", "key1",
                                 self.public_key, cache_timer=3600)
        self.assertEqual(self._count_rows(), 1)

        # Attempt injection via issuer in addkeyinfo (which DELETEs first)
        malicious_issuer = "x' OR '1'='1"
        self.keycache.addkeyinfo(malicious_issuer, "evil_key",
                                 self.public_key, cache_timer=3600)

        # The legitimate row must still exist, plus the new malicious-literal row
        self.assertEqual(self._count_rows(), 2)

    def test_injection_in_key_id_does_not_delete_other_rows(self):
        """
        A malicious key_id should not be able to affect other rows.
        """
        self.keycache.addkeyinfo("https://legit.example.com/", "key1",
                                 self.public_key, cache_timer=3600)
        self.assertEqual(self._count_rows(), 1)

        malicious_key_id = "x' OR '1'='1"
        self.keycache.addkeyinfo("https://other.example.com/", malicious_key_id,
                                 self.public_key, cache_timer=3600)

        self.assertEqual(self._count_rows(), 2)

    def test_delete_cache_entry_with_injection_string(self):
        """
        _delete_cache_entry with a crafted issuer must not delete unrelated rows.
        """
        self.keycache.addkeyinfo("https://legit.example.com/", "key1",
                                 self.public_key, cache_timer=3600)
        self.assertEqual(self._count_rows(), 1)

        # Try to delete with an injection string — should match nothing
        self.keycache._delete_cache_entry("x' OR '1'='1", "key1")
        self.assertEqual(self._count_rows(), 1)

    def test_union_select_injection_is_literal(self):
        """
        A UNION SELECT payload in the issuer should be stored as a literal
        value, not interpreted as SQL.
        """
        malicious_issuer = "x' UNION SELECT * FROM keycache --"
        self.keycache.addkeyinfo(malicious_issuer, "key1",
                                 self.public_key, cache_timer=3600)
        self.assertEqual(self._count_rows(), 1)

        # The stored issuer should be the literal malicious string
        conn = sqlite3.connect(self.keycache.cache_location)
        curs = conn.cursor()
        curs.execute("SELECT issuer FROM keycache")
        row = curs.fetchone()
        conn.close()
        self.assertEqual(row[0], malicious_issuer)

    def test_getkeyinfo_injection_issuer_no_leak(self):
        """
        getkeyinfo with an injection payload in issuer must not return
        rows belonging to a different issuer.
        """
        self.keycache.addkeyinfo("https://legit.example.com/", "key1",
                                 self.public_key, cache_timer=3600)

        # This injection string would match all rows with the old code
        malicious_issuer = "x' OR '1'='1"
        # getkeyinfo will not find a cached row and will try to download,
        # which will fail — that's expected.  The important thing is it
        # does NOT return the legit key.
        try:
            result = self.keycache.getkeyinfo(malicious_issuer, "key1")
        except Exception:
            result = None
        self.assertIsNone(result)

    def test_negative_cache_with_injection_string(self):
        """
        _add_negative_cache_entry with injection strings stores them literally.
        """
        malicious_issuer = "x' OR '1'='1"
        malicious_key_id = "y' DROP TABLE keycache --"
        self.keycache._add_negative_cache_entry(malicious_issuer, malicious_key_id, 300)
        self.assertEqual(self._count_rows(), 1)

        conn = sqlite3.connect(self.keycache.cache_location)
        curs = conn.cursor()
        curs.execute("SELECT issuer, key_id FROM keycache")
        row = curs.fetchone()
        conn.close()
        self.assertEqual(row[0], malicious_issuer)
        self.assertEqual(row[1], malicious_key_id)


if __name__ == '__main__':
    unittest.main()
