"""
Test for creating a simple scitoken.
"""

import os
import sys
import unittest

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")
if os.path.exists("../src"):
    sys.path.append("../src")

import scitokens
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class TestCreation(unittest.TestCase):
    """
    Test the creation of a simple SciToken
    """

    def setUp(self):
        self._private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        keycache = scitokens.utils.keycache.KeyCache.getinstance()
        keycache.addkeyinfo("local", "sample_key", self._private_key.public_key())
        self._token = scitokens.SciToken(key = self._private_key, key_id="sample_key")

    def test_create(self):
        """
        Test the creation of a simple SciToken.
        """
        print(self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        self._token.update_claims({"test": "true"})
        serialized_token = self._token.serialize(issuer = "local")

        self.assertEqual(len(serialized_token.decode('utf8').split(".")), 3)
        print(serialized_token)

    def test_serialize(self):
        with self.assertRaises(NotImplementedError):
            print(self._token.serialize(issuer="local", include_key=True))

        token = scitokens.SciToken()
        with self.assertRaises(scitokens.scitokens.MissingKeyException):
            print(token.serialize(issuer="local"))

        with self.assertRaises(scitokens.scitokens.MissingIssuerException):
            print(self._token.serialize())

        serialized_token = self._token.serialize(issuer="local")
        self.assertTrue(serialized_token)

        token = scitokens.SciToken.deserialize(serialized_token, insecure=True)
        self.assertTrue(isinstance(token, scitokens.SciToken))

        with self.assertRaises(NotImplementedError):
            print(scitokens.SciToken.deserialize(serialized_token, require_key=True, insecure=True))

        with self.assertRaises(scitokens.scitokens.InvalidTokenFormat):
            print(scitokens.SciToken.deserialize("asdf1234"))

    def test_create_to_validate(self):
        self._token['authz'] = 'write'
        self._token['path'] = '/home/example'
        serialized_token = self._token.serialize(issuer="local")
        token = scitokens.SciToken.deserialize(serialized_token)
        enf = scitokens.Enforcer(issuer="local")
        self.assertTrue(enf.test(token, "write", "/home/example/test_file"))
        self.assertFalse(enf.test(token, "read", "/home/example/test_file"))
        self.assertFalse(enf.test(token, "write", "/home/other/test_file"))

if __name__ == '__main__':
    unittest.main()
