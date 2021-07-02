"""
Test for using a configuration file
"""

import os
import unittest
import tempfile
import logging
import scitokens
import scitokens.utils.config

from six.moves import configparser

class TestConfig(unittest.TestCase):
    """
    Test the configuration parsing
    """

    def setUp(self):
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        scitokens.utils.config.configuration = configparser.ConfigParser(scitokens.utils.config.CONFIG_DEFAULTS)

    def tearDown(self):
        # Clear the config back to defaults each time
        scitokens.set_config()

    def test_config_file(self):
        """
        Test the configuration with a regular config file
        """
        # Get the current directory and pass it the path of test_config.ini
        scitokens.set_config(os.path.join(self.dir_path, "test_config.ini"))

        self.assertEqual(scitokens.utils.config.get("log_file"), "")
        self.assertEqual(scitokens.utils.config.get("log_level"), "DEBUG")

    def test_passing_config(self):
        """
        Test the passing of a configuration parser object
        """
        new_config = configparser.ConfigParser()
        new_config.add_section("scitokens")
        new_config.set("scitokens", "log_level", "WARNING")

        scitokens.set_config(new_config)

        self.assertEqual(scitokens.utils.config.get("log_level"), "WARNING")

    def test_passing_config_log(self):
        """
        Test the with log_file
        """

        new_config = configparser.ConfigParser()
        new_config.add_section("scitokens")
        new_config.set("scitokens", "log_level", "WARNING")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_file = os.path.join(tmp_dir, "tmp.log")
            new_config.set("scitokens", "log_file", tmp_file)

            scitokens.set_config(new_config)

            self.assertEqual(scitokens.utils.config.get("log_level"), "WARNING")
            self.assertEqual(scitokens.utils.config.get("log_file"), tmp_file)

            # Log a line
            logger = logging.getLogger("scitokens")
            logger.error("This is an error")
            self.assertTrue(os.path.getsize(tmp_file) > 0)

            # close the log files so that TemporaryDirectory can delete itself
            for handler in logger.handlers:
                handler.close()

    def test_no_config(self):
        """
        Test when there is no config
        """

        # This should throw an exception if there is an error
        self.assertEqual(scitokens.utils.config.get("cache_location"), "")
