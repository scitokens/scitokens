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
import cryptography.hazmat.primitives.asymmetric.ec as ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jwt import DecodeError, InvalidAudienceError
from scitokens.utils.errors import UnsupportedKeyException


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
        self._public_key = self._private_key.public_key()
        self._public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        keycache = scitokens.utils.keycache.KeyCache.getinstance()
        keycache.addkeyinfo("local", "sample_key", self._private_key.public_key())
        self._token = scitokens.SciToken(key = self._private_key, key_id="sample_key")
        self._no_kid_token = scitokens.SciToken(key = self._private_key)

    def test_create(self):
        """
        Test the creation of a simple SciToken.
        """

        token = scitokens.SciToken(key = self._private_key)
        token.update_claims({"test": "true"})
        serialized_token = token.serialize(issuer = "local")

        self.assertEqual(len(serialized_token.decode('utf8').split(".")), 3)
        print(serialized_token)

    def test_ec_create(self):
        """
        Test the creation of a simple Elliptical Curve token
        """
        ec_private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )

        token = scitokens.SciToken(key = ec_private_key, algorithm = "ES256")
        self.assertTrue(isinstance(ec_private_key, ec.EllipticCurvePrivateKey))
        token.update_claims({"test": "true"})
        serialized_token = token.serialize(issuer = "local")

        self.assertEqual(len(serialized_token.decode('utf8').split(".")), 3)
        print(serialized_token)


    def test_ec_public_key(self):
        """
        Test when the public key is provided to deserialize for Elliptical Curve
        """

        ec_private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
        ec_public_key = ec_private_key.public_key()
        ec_public_pem = ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        token = scitokens.SciToken(key = ec_private_key, algorithm = "ES256")
        serialized_token = token.serialize(issuer = "local")

        new_token = scitokens.SciToken.deserialize(serialized_token, public_key = ec_public_pem, insecure = True)
        self.assertIsInstance(new_token, scitokens.SciToken)

        # With invalid key
        with self.assertRaises(ValueError):
            scitokens.SciToken.deserialize(serialized_token, insecure=True, public_key = "asdf".encode())

        # With a proper key, but not the right one
        private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with self.assertRaises(DecodeError):
            scitokens.SciToken.deserialize(serialized_token, insecure=True, public_key = pem)

    def test_public_key(self):
        """
        Test when the public key is provided to deserialize
        """

        token = scitokens.SciToken(key = self._private_key)
        serialized_token = token.serialize(issuer = "local")

        new_token = scitokens.SciToken.deserialize(serialized_token, public_key = self._public_pem, insecure = True)
        self.assertIsInstance(new_token, scitokens.SciToken)

        # With invalid key
        with self.assertRaises(ValueError):
            scitokens.SciToken.deserialize(serialized_token, insecure=True, public_key = "asdf".encode())

        # With a proper key, but not the right one
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with self.assertRaises(DecodeError):
            scitokens.SciToken.deserialize(serialized_token, insecure=True, public_key = pem)




    def test_aud(self):
        """
        Test the audience argument to deserialize
        """
        token = scitokens.SciToken(key = self._private_key)
        token.update_claims({'aud': 'local'})

        serialized_token = token.serialize(issuer = 'local')

        with self.assertRaises(InvalidAudienceError):
            scitokens.SciToken.deserialize(serialized_token, public_key = self._public_pem, insecure = True)

        new_token = scitokens.SciToken.deserialize(serialized_token,
                                                   public_key = self._public_pem,
                                                   insecure = True,
                                                   audience = 'local')
        self.assertIsInstance(new_token, scitokens.SciToken)

    def test_serialize(self):
        """
        Test various edge cases of serialization, particularly around failures.
        """
        with self.assertRaises(NotImplementedError):
            print(self._token.serialize(issuer="local", include_key=True))

        token = scitokens.SciToken()
        with self.assertRaises(scitokens.utils.errors.MissingKeyException):
            print(token.serialize(issuer="local"))

        with self.assertRaises(scitokens.scitokens.MissingIssuerException):
            print(self._token.serialize())

        serialized_token = self._token.serialize(issuer="local")
        self.assertTrue(serialized_token)

        token = scitokens.SciToken.deserialize(serialized_token, public_key = self._public_pem, insecure=True)
        self.assertTrue(isinstance(token, scitokens.SciToken))

        with self.assertRaises(NotImplementedError):
            print(scitokens.SciToken.deserialize(serialized_token, require_key=True, insecure=True))

        with self.assertRaises(scitokens.scitokens.InvalidTokenFormat):
            print(scitokens.SciToken.deserialize("asdf1234"))

    def test_create_to_validate(self):
        """
        End-to-end test of SciToken creation, verification, and validation.
        """
        self._token['scope'] = "write:/home/example"
        serialized_token = self._token.serialize(issuer="local")
        token = scitokens.SciToken.deserialize(serialized_token, public_key = self._public_pem, insecure=True)
        enf = scitokens.Enforcer(issuer="local")
        self.assertTrue(enf.test(token, "write", "/home/example/test_file"), msg=enf.last_failure)
        self.assertFalse(enf.test(token, "read", "/home/example/test_file"))
        self.assertFalse(enf.test(token, "write", "/home/other/test_file"))

    def test_multiple_scopes(self):
        """
        End-to-end test of SciToken creation, verification, and validation with multiple scopes.
        """
        self._token['scope'] = "write:/home/example read:/home/read"
        serialized_token = self._token.serialize(issuer="local")
        token = scitokens.SciToken.deserialize(serialized_token, public_key = self._public_pem, insecure=True)
        enf = scitokens.Enforcer(issuer="local")
        self.assertTrue(enf.test(token, "write", "/home/example/test_file"), msg=enf.last_failure)
        self.assertFalse(enf.test(token, "read", "/home/example/test_file"))
        self.assertFalse(enf.test(token, "write", "/home/other/test_file"))
        self.assertTrue(enf.test(token, "read", "/home/read/test_file"))

    def test_ver(self):
        """
        Testing the version attribute
        """
        self._token['ver'] = 1
        self._token['scope'] = "write:/home/example"
        enf = scitokens.Enforcer(issuer="local")
        self.assertTrue(enf.test(self._token, "write", "/home/example/test_file"))

        # Now set it to a number it shouldn't understand
        self._token['ver'] = 9999
        self.assertFalse(enf.test(self._token, "write", "/home/example/test_file"))

    def test_opt(self):
        """
        Testing the version attribute
        """
        self._token['opt'] = "This is optional information, and should always return true"
        self._token['scope'] = "write:/home/example"
        enf = scitokens.Enforcer(issuer="local")
        self.assertTrue(enf.test(self._token, "write", "/home/example/test_file"))

    def test_contains(self):
        """
        Testing the contains attribute
        """
        self._token['opt'] = "This is optional information, and should always return true"
        self._token['scp'] = "write:/home/example"

        self.assertTrue('opt' in self._token)
        self.assertTrue('scp' in self._token)
        self.assertFalse('notin' in self._token)

    def test_no_kid(self):
        """
        Testing a token without a kid
        """
        serialized_token = self._no_kid_token.serialize(issuer = 'local')
        print(serialized_token)

        token = scitokens.SciToken.deserialize(serialized_token, public_key = self._public_pem, insecure=True)

    def test_unsupported_key(self):
        """
        Test a token with an unsupported key algorithm
        """
        with self.assertRaises(UnsupportedKeyException):
            scitokens.SciToken(key = self._private_key, algorithm="doesnotexist")

    def test_autodetect_keytype(self):
        """
        Test the autodetection of the key type
        """
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        ec_private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )

        # Test when we give it the wrong algorithm type
        with self.assertRaises(scitokens.scitokens.UnsupportedKeyException):
            token = scitokens.SciToken(key = private_key, algorithm="ES256")

        # Test when we give it the wrong algorithm type
        with self.assertRaises(scitokens.scitokens.UnsupportedKeyException):
            token = scitokens.SciToken(key = ec_private_key, algorithm="RS256")

        # Test when we give an unsupported algorithm
        unsupported_private_key = ec.generate_private_key(
            ec.SECP192R1(), default_backend()
        )
        with self.assertRaises(scitokens.scitokens.UnsupportedKeyException):
            token = scitokens.SciToken(key = unsupported_private_key)

        token = scitokens.SciToken(key = ec_private_key, algorithm="ES256")
        token.serialize(issuer="local")

if __name__ == '__main__':
    unittest.main()
