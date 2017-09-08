
import os
import sys
import unittest

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")

import scitokens


class TestValidation(unittest.TestCase):

    def test_valid(self):

        def always_accept(value):
            return True

        validator = scitokens.Validator()
        validator.add_validator("foo", always_accept)

        token = scitokens.SciToken()
        token["foo"] = "bar"

        self.assertTrue(validator.validate(token))
        self.assertTrue(validator(token))


if __name__ == '__main__':
    unittest.main()
