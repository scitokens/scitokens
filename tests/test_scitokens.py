
"""
Test cases for the Validator and Enforcer classes from the scitokens module.
"""

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
    """
    Tests related to the Validator object.
    """

    def test_valid(self):
        """
        Basic unit test coverage of the Validator object.
        """

        def always_accept(value):
            """
            A validator that accepts any value.
            """
            if value or not value:
                return True

        validator = scitokens.Validator()
        validator.add_validator("foo", always_accept)

        token = scitokens.SciToken()
        token["foo"] = "bar"

        self.assertTrue(validator.validate(token))
        self.assertTrue(validator(token))


class TestEnforcer(unittest.TestCase):
    """
    Unit tests for the SciToken's Enforcer object.
    """

    _test_issuer = "https://scitokens.org/unittest"

    @staticmethod
    def always_accept(value):
        if value or not value:
            return True

    def setUp(self):
        """
        Setup a sample token for testing the enforcer.
        """
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
        self._token["iss"] = self._test_issuer
        self._token["nbf"] = int(now)

        # Scitoken v2
        self._token2 = scitokens.SciToken(key=private_key)
        self._token2["ver"] = "scitoken:2.0"
        self._token2["foo"] = "bar"
        self._token2["iat"] = int(now)
        self._token2["exp"] = int(now + 600)
        self._token2["iss"] = self._test_issuer
        self._token2["nbf"] = int(now)
        self._token2['wlcg.groups'] = ['groupA', 'groupB']
        self._token2["aud"] = "ANY"


    def test_enforce_v2(self):
        """
        Test the Enforcer object for profile scitokens:2.0
        Also, there is a non-validated attribute, foo.  In 1.0, non-validated attributes
        cause a validation error.  In 2.0, they are ignored.
        """
        with self.assertRaises(scitokens.scitokens.EnforcementError):
            print(scitokens.Enforcer(None))

        # No audience specified
        enf = scitokens.Enforcer(self._test_issuer)
        self.assertFalse(enf.test(self._token2, "read", "/"), msg=enf.last_failure)
        self._token2["scp"] = "read:/"
        self.assertFalse(enf.test(self._token2, "read", "/"), msg=enf.last_failure)

        # Token is set to to ANY, so any audience will work
        enf = scitokens.Enforcer(self._test_issuer, audience = "https://example.unl.edu")
        self._token2["scp"] = "read:/"
        self.assertTrue(enf.test(self._token2, "read", "/"), msg=enf.last_failure)

        # Change the audience from ANY to https://example.com
        self._token2["aud"] = "https://example.com"
        self.assertFalse(enf.test(self._token2, "read", "/"), msg=enf.last_failure)

        # Change back to ANY
        self._token2["aud"] = "ANY"
        self.assertTrue(enf.test(self._token2, "read", "/"), msg=enf.last_failure)

        self._token2["scp"] = "read:/foo/bar"
        self.assertFalse(enf.test(self._token2, "read", "/foo"), msg=enf.last_failure)

        self.assertFalse(enf.test(self._token2, "write", "/foo/bar"), msg=enf.last_failure)

        with self.assertRaises(scitokens.scitokens.InvalidPathError):
            print(enf.test(self._token2, "write", "~/foo"))
    

    def test_v2(self):
        """
        Test the requirements for a v2
        """
        # First, delete the aud
        del self._token2["aud"]
        enf = scitokens.Enforcer(self._test_issuer, audience="https://example.unl.edu")
        self._token2["scope"] = "read:/foo/bar"
        # Should fail, audience is required for 2.0 token
        self.assertFalse(enf.test(self._token2, "read", "/foo/bar"), msg=enf.last_failure)

        # Now set the audience to ANY
        self._token2["aud"] = "ANY"
        self.assertTrue(enf.test(self._token2, "read", "/foo/bar"), msg=enf.last_failure)

        # Now to the correct audience
        self._token2["aud"] = "https://example.unl.edu"
        self.assertTrue(enf.test(self._token2, "read", "/foo/bar"), msg=enf.last_failure)

        # Now to the wrong audience
        self._token2["aud"] = "https://example.com"
        self.assertFalse(enf.test(self._token2, "read", "/foo/bar"), msg=enf.last_failure)

        # Arbitrary claims are allowed now in v2
        self._token2["madeupclaim"] = "claimsdontmatter"
        self._token2["aud"] = "ANY"
        self.assertTrue(enf.test(self._token2, "read", "/foo/bar"), msg=enf.last_failure)

        # Arbitrary claims should fail in 1.0
        self._token["madeupclaim"] = "claimsdontmatter"
        self._token["aud"] = "ANY"
        self.assertFalse(enf.test(self._token, "read", "/foo/bar"), msg=enf.last_failure)


    def test_enforce(self):
        """
        Test the Enforcer object.
        """
        with self.assertRaises(scitokens.scitokens.EnforcementError):
            print(scitokens.Enforcer(None))

        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", self.always_accept)

        self.assertFalse(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        self._token["scp"] = "read:/"
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        enf = scitokens.Enforcer(self._test_issuer, audience = "https://example.unl.edu")
        enf.add_validator("foo", self.always_accept)
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        self._token["scp"] = "read:/foo/bar"
        self.assertFalse(enf.test(self._token, "read", "/foo"), msg=enf.last_failure)

        self.assertTrue(enf.test(self._token, "read", "/foo/bar"), msg=enf.last_failure)
        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", self.always_accept)
        self.assertTrue(enf.test(self._token, "read", "/foo/bar"), msg=enf.last_failure)

        self.assertFalse(enf.test(self._token, "write", "/foo/bar"), msg=enf.last_failure)

        with self.assertRaises(scitokens.scitokens.InvalidPathError):
            print(enf.test(self._token, "write", "~/foo"))

    def test_enforce_scope(self):
        """
        Test the Enforcer object.
        """
        with self.assertRaises(scitokens.scitokens.EnforcementError):
            print(scitokens.Enforcer(None))

        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", self.always_accept)

        self.assertFalse(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        self._token["scope"] = "read:/"
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        enf = scitokens.Enforcer(self._test_issuer, audience = "https://example.unl.edu")
        enf.add_validator("foo", self.always_accept)
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        self._token["scope"] = "read:/foo/bar"
        self.assertFalse(enf.test(self._token, "read", "/foo"), msg=enf.last_failure)

        self.assertTrue(enf.test(self._token, "read", "/foo/bar"), msg=enf.last_failure)
        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", self.always_accept)
        self.assertTrue(enf.test(self._token, "read", "/foo/bar"), msg=enf.last_failure)

        self.assertFalse(enf.test(self._token, "write", "/foo/bar"), msg=enf.last_failure)

        with self.assertRaises(scitokens.scitokens.InvalidPathError):
            print(enf.test(self._token, "write", "~/foo"))


    def test_aud(self):
        """
        Test the audience claim
        """
        self._token['scp'] = 'read:/'
        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", lambda path : True)
        self._token['aud'] = "https://example.unl.edu"
        self.assertFalse(enf.test(self._token, "read", "/"), msg=enf.last_failure)

        enf = scitokens.Enforcer(self._test_issuer, audience = "https://example.unl.edu")
        enf.add_validator("foo", lambda path : True)
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)

    def test_multiple_aud(self):
        """
        Test multiple aud
        """
        self._token['scp'] = 'read:/'

        # Test multiple audiences
        enf = scitokens.Enforcer(self._test_issuer, audience = ["https://example.unl.edu", "https://another.com"])
        enf.add_validator("foo", self.always_accept)
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)
        self._token['aud'] = "https://another.com"
        self.assertTrue(enf.test(self._token, "read", "/"), msg=enf.last_failure)
        self._token['aud'] = "https://doesnotwork.com"
        self.assertFalse(enf.test(self._token, "read", "/"), msg=enf.last_failure)

    def test_getitem(self):
        """
        Test the getters for the SciTokens object.
        """
        self.assertEqual(self._token['foo'], 'bar')
        with self.assertRaises(KeyError):
            print(self._token['bar'])
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
        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", self.always_accept)

        self._token['scope'] = 'read:/'
        acls = enf.generate_acls(self._token)
        self.assertTrue(len(acls), 1)
        self.assertEqual(acls[0], ('read', '/'))

        self._token['scope'] = 'read:/ write:/foo'
        acls = enf.generate_acls(self._token)
        self.assertTrue(len(acls), 2)
        self.assertTrue(('read', '/') in acls)
        self.assertTrue(('write', '/foo') in acls)

        self._token['scope'] = 'read:/foo read://bar write:/foo write://bar'
        acls = enf.generate_acls(self._token)
        self.assertTrue(len(acls), 4)
        self.assertTrue(('read', '/foo') in acls)
        self.assertTrue(('write', '/foo') in acls)
        self.assertTrue(('read', '/bar') in acls)
        self.assertTrue(('write', '/bar') in acls)

        self._token['exp'] = time.time() - 600
        with self.assertRaises(scitokens.scitokens.ClaimInvalid):
            print(enf.generate_acls(self._token))
        self.assertTrue(enf.last_failure)
        self._token['exp'] = time.time() + 600

        self._token['scope'] = 'read:foo'
        with self.assertRaises(scitokens.scitokens.InvalidAuthorizationResource):
            print(enf.generate_acls(self._token))

        self._token['scope'] = 'read'
        with self.assertRaises(scitokens.scitokens.InvalidAuthorizationResource):
            print(enf.generate_acls(self._token))

    def test_sub(self):
        """
        Verify that tokens with the `sub` set are accepted.
        """
        self._token['sub'] = 'Some Great User'
        enf = scitokens.Enforcer(self._test_issuer)
        enf.add_validator("foo", self.always_accept)

        self._token['scope'] = 'read:/'
        acls = enf.generate_acls(self._token)
        self.assertTrue(len(acls), 1)

if __name__ == '__main__':
    unittest.main()
