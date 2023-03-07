"""
Test demo module 
"""

import scitokens.utils.demo
import unittest


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
        token = scitokens.SciToken.deserialize(token_serialized)            # automatically call verify 
        
        # assert that the payload is part of the claims
        for key, value in payload.items(): 
            self.assertIn((key, value), token.claims())


    def test_empty_payload(self): 
        """
        Test token with empty payload
        """    
        payload = {}
        token_serialized = scitokens.utils.demo.token(payload)  
        token = scitokens.SciToken.deserialize(token_serialized) 


class TestParsedToken(unittest.TestCase): 
    def test_valid_parsed(self): 
        """
        Test that the parsed token matches the payload
        """
        payload = {
            "key1": "val1", 
            "key2": "val2"
            }

        token = scitokens.utils.demo.parsed_token(payload)
        for key, value in payload.items(): 
            self.assertIn((key, value), token.claims())

    def test_empty_parsed(self): 
        """
        Test token with empty payload
        """
        payload = {}
        token = scitokens.utils.demo.parsed_token(payload)


if __name__ == '__main__':
    unittest.main()

