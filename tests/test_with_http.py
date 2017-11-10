"""
Test the full HTTP to SciToken serialize and deserialize
"""

import os
import sys
import unittest
import threading
import base64

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")
if os.path.exists("../src"):
    sys.path.append("../src")

import scitokens
import scitokens.scitokens

import cryptography.utils
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from create_webserver import start_server

class TestDeserialization(unittest.TestCase):
    """
    Test the deserialization of a SciToken
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_deserialization(self):
        """
        Perform the deserialization test
        """
        with open('tests/simple_private_key.pem', 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        TEST_ID = "stuffblah"

        public_numbers = private_key.public_key().public_numbers()
        server_address = start_server(public_numbers.n, public_numbers.e, TEST_ID)
        print(server_address)
        issuer = "http://localhost:{}/".format(server_address[1])
        token = scitokens.SciToken(key=private_key, key_id=TEST_ID)
        token.update_claims({"test": "true"})
        serialized_token = token.serialize(issuer=issuer)

        self.assertEqual(len(serialized_token.decode('utf8').split(".")), 3)

        scitoken = scitokens.SciToken.deserialize(serialized_token, insecure=True)

        self.assertIsInstance(scitoken, scitokens.SciToken)

        token = scitokens.SciToken(key=private_key, key_id="doesnotexist")
        serialized_token = token.serialize(issuer=issuer)
        with self.assertRaises(scitokens.utils.errors.MissingKeyException):
            scitoken = scitokens.SciToken.deserialize(serialized_token, insecure=True)




if __name__ == '__main__':
    unittest.main()
