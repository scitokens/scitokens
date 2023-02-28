import scitokens.utils.demo
import unittest


class TestDemo(unittest.TestCase):
    def test_valid_token(self):
        """
        Test that the token matches the specified payload
        """
        payload = {
            "key1": "value1",
            "key2": "value2",
            "key3": "value3",
            }
        
        token_serialized = scitokens.utils.demo.token(payload)
        token = scitokens.SciToken.deserialize(token_serialized)            # automatically call verify 
    
        # assert that the payload is part of the claims
        for key, value in payload.items(): 
            self.assertIn((key, value), token.claims())

        # validate the token 
        val = scitokens.Validator()
        self.assertTrue(val.validate(token))


if __name__ == '__main__':
    unittest.main()

