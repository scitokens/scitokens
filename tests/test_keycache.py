"""
Test the keycache

"""

import os
import tempfile
import shutil
import unittest
from scitokens.utils.keycache import KeyCache


class TestKeyCache(unittest.TestCase):
    """
    Test the creation of a simple SciToken
    """
    
    
    def setUp(self):
        # Clear the cache
        keycache = KeyCache().getinstance()

        # Force the keycache to create a cache in a new directory
        self.tmp_dir = tempfile.mkdtemp()
        os.environ['XDG_CACHE_HOME'] = self.tmp_dir
        keycache.cache_location = keycache._get_cache_file()

        # make sure it made the directory where I wanted it
        self.assertTrue(keycache.cache_location.startswith(self.tmp_dir))
        self.assertTrue(os.path.exists(keycache.cache_location))
        
    
    def tearDown(self):
        shutil.rmtree(self.tmp_dir)
    
    
    def test_empty(self):
        pass
    

    def test_populated(self):
        pass
    

