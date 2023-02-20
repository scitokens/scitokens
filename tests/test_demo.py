import scitokens.utils.demo
import unittest
# writing test & documetation
# read how python library works
class TestDemo(unittest.TestCase):
    def setUp(self):
    

        # Force the keycache to create a cache in a new directory
        self.tmp_dir = tempfile.mkdtemp()
        self.old_xdg = os.environ.get('XDG_DEMO_HOME', None)
        os.environ['XDG_DEMO_HOME'] = self.tmp_dir
        # Clear the cache
        self.keycache = Demo()

        # make sure it made the directory where I wanted it
        self.assertTrue(self.keycache.cache_location.startswith(self.tmp_dir))
        self.assertTrue(os.path.exists(self.keycache.cache_location))


    def tearDown(self):
        shutil.rmtree(self.tmp_dir)
        if self.old_xdg:
            os.environ['XDG_DEMO_HOME'] = self.old_xdg