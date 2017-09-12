
import os
import sys
import time
import unittest

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
        self._token = scitokens.SciToken()
        self._token["foo"] = "bar"
        self._token["iat"] = int(now)
        self._token["exp"] = int(now + 600)
        self._token["iss"] = "https://scitokens.org/unittest"
        self._token["nbf"] = int(now)

    def test_enforce(self):

        def always_accept(value):
            if value or not value:
                return True

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


if __name__ == '__main__':
    unittest.main()
