"""
Test the keycache
"""

import os
import logging
import tempfile
import shutil
import threading
import unittest
from scitokens.utils.keycache import KeyCache


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
        import time
        for attempt in range(5):
            try:
                shutil.rmtree(self.tmp_dir)
                break
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(1)
        if self.old_xdg:
            os.environ['XDG_CACHE_HOME'] = self.old_xdg
        # Clean up, delete everything

    def test_clients_calling_valid_keys(self):
        """
        Test when there are many clients calling valid keys at the same time
        """
        # Thread Job
        def client_job(issuer, key_id):
            keycache = KeyCache()
            res = keycache.add_key(issuer, key_id, False)
            logger = logging.getLogger("scitokens")
            logger.warning(res)
        threads = []
        key = ('https://demo.scitokens.org', 'key-rs256')
        for _ in range(2000):
            thread = threading.Thread(target=client_job, args=key)
            threads.append(thread)
            thread.start()
        for thread in threads:  # iterates over the threads
            thread.join()

    def test_clients_calling_invalid_keys(self):
        """
        Test when there are many clients calling valid keys at the same time
        """
        # Thread Job
        def client_job(issuer, key_id):
            keycache = KeyCache()
            res = keycache.add_key(issuer, key_id, False)
            logger = logging.getLogger("scitokens")
            logger.warning(res)
        threads = []
        key = ('minh', 'vy')
        for _ in range(200):
            thread = threading.Thread(target=client_job, args=key)
            threads.append(thread)
            thread.start()
        for thread in threads:  # iterates over the threads
            thread.join()

if __name__ == '__main__':
    unittest.main()