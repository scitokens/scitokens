"""
Test the full HTTP to SciToken serialize and deserialize
"""

import os
import sys
import unittest
import threading
import base64

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")
if os.path.exists("../src"):
    sys.path.append("../src")

import scitokens
import scitokens.scitokens

import cryptography.utils
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.backends import default_backend

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer
import json

# For use in the HTTP Serve test class
#test_kid = ""
TEST_N = 0
TEST_E = 0
TEST_ID = ""

def bytes_from_long(data):
    """
    Create a base64 encoded string for an integer
    """
    return base64.urlsafe_b64encode(cryptography.utils.int_to_bytes(data)).decode('ascii')

class OauthRequestHandler(BaseHTTPRequestHandler):
    """
    Request handler for the HTTP requests to authenticate deserialization of a SciToken
    """
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/json')
        self.end_headers()

    def do_GET(self): # pylint: disable=invalid-name
        """
        Receive the GET command for the oauth certs
        """
        global TEST_N
        global TEST_E

        # Make sure the User-Agent is SciTokens*
        user_agent = self.headers.get('User-Agent')
        if not user_agent.startswith("SciTokens"):
            self.send_response(404)
            return
        self._set_headers()
        to_write = ""
        if self.path == "/.well-known/openid-configuration":
            to_write = json.dumps({"jwks_uri": "http://localhost:8080/oauth2/certs"})
        elif self.path == "/oauth2/certs":

            # Dummy Key
            dummy_key = {
                'kid': 'dummykey',
                'n': 'reallylongn',
                'e': 'AQAB',
                'alg': "RS256",
                'kty': "RSA"
            }

            key_info = {}
            key_info['kid'] = TEST_ID
            key_info['n'] = bytes_from_long(TEST_N)
            key_info['e'] = bytes_from_long(TEST_E)
            key_info['kty'] = "RSA"
            key_info['alg'] = "RS256"

            to_write = json.dumps({'keys': [dummy_key, key_info]})
        self.wfile.write(to_write.encode())



class TestDeserialization(unittest.TestCase):
    """
    Test the deserialization of a SciToken
    """

    def setUp(self):
        # Start a web server to act as the "issuer"
        server_address = ('', 8080)
        self.httpd = HTTPServer(server_address, OauthRequestHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def tearDown(self):
        del self.httpd
        del self.thread

    def test_deserialization(self):
        """
        Perform the deserialization test
        """
        global TEST_N
        global TEST_E
        global TEST_ID
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        TEST_ID = "stuffblah"

        token = scitokens.SciToken(key=private_key, key_id=TEST_ID)
        token.update_claims({"test": "true"})
        serialized_token = token.serialize(issuer="http://localhost:8080/")

        public_numbers = private_key.public_key().public_numbers()
        TEST_E = public_numbers.e
        TEST_N = public_numbers.n

        self.assertEqual(len(serialized_token.decode('utf8').split(".")), 3)

        scitoken = scitokens.SciToken.deserialize(serialized_token, insecure=True)

        self.assertIsInstance(scitoken, scitokens.SciToken)

        token = scitokens.SciToken(key=private_key, key_id="doesnotexist")
        serialized_token = token.serialize(issuer="http://localhost:8080/")
        with self.assertRaises(scitokens.scitokens.MissingKeyException):
            scitoken = scitokens.SciToken.deserialize(serialized_token, insecure=True)




if __name__ == '__main__':
    unittest.main()
