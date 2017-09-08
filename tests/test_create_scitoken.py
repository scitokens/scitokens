

import os
import sys
import unittest

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")
if os.path.exists("../src"):
    sys.path.append("../src")

import scitokens
import cryptography
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class TestCreation(unittest.TestCase):

    def test_create(self):
        
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        print(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        token = scitokens.SciToken(key = private_key)
        token.update_claims({"test": "true"})
        serialized_token = token.serialize(issuer = "local")
        
        self.assertEqual(len(serialized_token.split(".")), 3)
        print(serialized_token)
        
        



if __name__ == '__main__':
    unittest.main()
