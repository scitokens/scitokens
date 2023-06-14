"""
Test demo module
"""

import scitokens.utils.demo
import unittest
import jwt          # to handle jwt exceptions
import time         # to add time delay


class TestToken(unittest.TestCase):
    def test_valid_payload(self):
        """
        Test that the token matches the specified payload
        """
        payload = {
            "key1": "val1",
            "key2": "val2"
            }

        token_serialized = scitokens.utils.demo.token(payload)
        try:
            token = scitokens.SciToken.deserialize(token_serialized)            # automatically call verify
        except jwt.exceptions.ImmatureSignatureError:                           # if the token was issued in the future
            print("Token not yet valid. Retrying in 1 second.")
            time.sleep(10)                                                       # add some delay
            token = scitokens.SciToken.deserialize(token_serialized)            # retry
        # assert that the payload is part of the claims
        for key, value in payload.items():
            self.assertIn((key, value), token.claims())


    def test_empty_payload(self):
        """
        Test token with empty payload
        """
        payload = {}
        token_serialized = scitokens.utils.demo.token(payload)
        try:
            scitokens.SciToken.deserialize(token_serialized)            # automatically call verify
        except jwt.exceptions.ImmatureSignatureError:
            print("Token not yet valid. Retrying in 1 second.")
            time.sleep(10)
            scitokens.SciToken.deserialize(token_serialized)


class TestParsedToken(unittest.TestCase):
    def test_valid_parsed(self):
        """
        Test that the parsed token matches the payload
        """
        payload = {
            "key1": "val1",
            "key2": "val2"
            }

        try:
            token = scitokens.utils.demo.parsed_token(payload)
        except jwt.exceptions.ImmatureSignatureError:
            print("Token was immature, but that might be ok.  Not throwing error, already tested in token")
            return
        for key, value in payload.items():
            self.assertIn((key, value), token.claims())


    def test_empty_parsed(self):
        """
        Test token with empty payload
        """
        payload = {}
        try:
            scitokens.utils.demo.parsed_token(payload)
        except jwt.exceptions.ImmatureSignatureError:
            print("Token was immature, but that might be ok.  Not throwing error, already tested in token")



if __name__ == '__main__':
    unittest.main()

