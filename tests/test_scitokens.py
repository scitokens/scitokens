
import os
import sys
import time
import unittest

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.rsa

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")
if os.path.exists("../src"):
    sys.path.append("../src")

import scitokens


class TestValidation(unittest.TestCase):

    def test_valid(self):

        def always_accept(value):
            if value or not value:
                return True

        validator = scitokens.Validator()
        validator.add_validator("foo", always_accept)

        token = scitokens.SciToken()
        token["foo"] = "bar"

        self.assertTrue(validator.validate(token))
        self.assertTrue(validator(token))


class TestEnforcer(unittest.TestCase):

    _test_issuer = "https://scitokens.org/unittest"

    def setUp(self):
        now = time.time()
        private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=cryptography.hazmat.backends.default_backend()
        )
        self._token = scitokens.SciToken(key=private_key)
        self._token["foo"] = "bar"
        self._token["iat"] = int(now)
        self._token["exp"] = int(now + 600)
        self._token["iss"] = "https://scitokens.org/unittest"
        self._token["nbf"] = int(now)

    def test_enforce(self):
        """
        Test the Enforcer object.
        """
        def always_accept(value):
            if value or not value:
                return True

        with self.assertRaises(scitokens.scitokens.EnforcementError):
            print scitokens.Enforcer(None)

        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", always_accept)

        self.assertFalse(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        self._token["authz"] = "read"
        self._token["path"] = "/"
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        enf = scitokens.Enforcer(self._test_issuer, audience = "https://example.unl.edu")
        enf.add_validator("foo", always_accept)
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        self._token["path"] = "/foo/bar"
        self.assertFalse(enf.test(self._token, "read", "/foo"), msg=enf.last_failure)

        self._token["site"] = "T2_US_Example"
        self.assertFalse(enf.test(self._token, "read", "/foo/bar"), msg=enf.last_failure)
        enf = scitokens.Enforcer(self._test_issuer, site="T2_US_Example")
        enf.add_validator("foo", always_accept)
        self.assertTrue(enf.test(self._token, "read", "/foo/bar"), msg=enf.last_failure)

    def test_aud(self):
        """
        Test the audience claim
        """
        self._token['path'] = '/'
        self._token['authz'] = 'read'
        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", lambda path : True)
        self._token['aud'] = "https://example.unl.edu"
        self.assertFalse(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        enf = scitokens.Enforcer(self._test_issuer, audience = "https://example.unl.edu")
        enf.add_validator("foo", lambda path : True)
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

    def test_getitem(self):
        """
        Test the getters for the SciTokens object.
        """
        self.assertEqual(self._token['foo'], 'bar')
        with self.assertRaises(KeyError):
            print self._token['bar']
        self.assertEqual(self._token.get('baz'), None)
        self.assertEqual(self._token.get('foo', 'baz'), 'bar')
        self.assertEqual(self._token.get('foo', 'baz', verified_only=True), 'baz')
        self._token.serialize()
        self.assertEqual(self._token['foo'], 'bar')
        self.assertEqual(self._token.get('foo', 'baz'), 'bar')
        self.assertEqual(self._token.get('bar', 'baz'), 'baz')
        self.assertEqual(self._token.get('bar', 'baz', verified_only=True), 'baz')
        self._token['bar'] = '1'
        self.assertEqual(self._token.get('bar', 'baz', verified_only=False), '1')
        self.assertEqual(self._token.get('bar', 'baz', verified_only=True), 'baz')

    def test_gen_acls(self):
        """
        Test the generation of ACLs
        """
        def always_accept(value):
            if value or not value:
                return True

        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", always_accept)

        self._token['authz'] = 'read'
        self._token['path'] = '/'
        acls = enf.generate_acls(self._token)
        self.assertTrue(len(acls), 1)
        self.assertEquals(acls[0], ('read', '/'))

        self._token['authz'] = ['read', 'write']
        acls = enf.generate_acls(self._token)
        self.assertTrue(len(acls), 2)
        self.assertTrue(('read', '/') in acls)
        self.assertTrue(('write', '/') in acls)

        self._token['path'] = ['/foo', '//bar']
        acls = enf.generate_acls(self._token)
        self.assertTrue(len(acls), 4)
        self.assertTrue(('read', '/foo') in acls)
        self.assertTrue(('write', '/foo') in acls)
        self.assertTrue(('read', '/bar') in acls)
        self.assertTrue(('write', '/bar') in acls)

        self._token['exp'] = time.time() - 600
        with self.assertRaises(scitokens.scitokens.ClaimInvalid):
            print enf.generate_acls(self._token)
        self.assertTrue(enf.last_failure)
        self._token['exp'] = time.time() + 600

        self._token['path'] = 'foo'
        with self.assertRaises(scitokens.scitokens.InvalidPathError):
            print enf.generate_acls(self._token)


if __name__ == '__main__':
    unittest.main()
