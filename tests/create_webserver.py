"""
Utility to create a simple webserver that will answer oauth .well-known
required requests.  This is so we can test the HTTP requesting part of issuers.
"""

import threading
import json
try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer

import scitokens.utils

# For use in the HTTP Serve test class
#test_kid = ""
TEST_N = 0
TEST_E = 0
TEST_ID = ""
HTTPD = None
THREAD = None
EC_TEST_ID = ""
EC_TEST_X = 0
EC_TEST_Y = 0

class OauthRequestHandler(BaseHTTPRequestHandler):
    """
    Request handler for the HTTP requests to authenticate deserialization of a SciToken
    """
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/json')
        self.send_header('Cache-Control', 'max-age=3600')
        self.end_headers()

    def do_GET(self): # pylint: disable=invalid-name
        """
        Receive the GET command for the oauth certs
        """
        global TEST_N
        global TEST_E
        global HTTPD
        global EC_TEST_ID
        global EC_TEST_X
        global EC_TEST_Y


        # Make sure the User-Agent is SciTokens*
        user_agent = self.headers.get('User-Agent')
        if not user_agent.startswith("SciTokens"):
            self.send_response(404)
            return
        self._set_headers()
        to_write = ""
        if self.path == "/.well-known/openid-configuration":
            to_write = json.dumps({"jwks_uri": "http://localhost:{}/oauth2/certs".format(HTTPD.server_address[1])})
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
            key_info['n'] = scitokens.utils.bytes_from_long(TEST_N).decode('ascii')
            key_info['e'] = scitokens.utils.bytes_from_long(TEST_E).decode('ascii')
            key_info['kty'] = "RSA"
            key_info['alg'] = "RS256"

            if EC_TEST_ID and EC_TEST_X and EC_TEST_Y:
                ec_key_info = {
                    'kid': EC_TEST_ID,
                    'kty': "EC",
                    'crv': "P-256",
                    'x': scitokens.utils.bytes_from_long(EC_TEST_X).decode('ascii'),
                    'y': scitokens.utils.bytes_from_long(EC_TEST_Y).decode('ascii')
                }
                to_write = json.dumps({'keys': [dummy_key, key_info, ec_key_info]})
            else:
                to_write = json.dumps({'keys': [dummy_key, key_info]})

        self.wfile.write(to_write.encode())


def start_server(test_n, test_e, test_id, test_ec = None):
    """
    Man this is ugly.  But you have to set global variables because it's
    impossible to send arguments to the HTTPServer, since you pass the HTTPServer
    as a type, not an instance.

    :param long int test_n: N for an RSA key
    :param long int test_e: E for an RSA key
    :param str test_id: Key ID for the test key
    :param dict test_ec: If you would like to test EC, then set the data structure to:
        kid, x, y
    """
    global TEST_N
    global TEST_E
    global TEST_ID
    global THREAD
    global HTTPD
    global EC_TEST_ID
    global EC_TEST_X
    global EC_TEST_Y

    TEST_N = test_n
    TEST_E = test_e
    TEST_ID = test_id

    if test_ec:
        EC_TEST_ID = test_ec['kid']
        EC_TEST_X = test_ec['x']
        EC_TEST_Y = test_ec['y']

    server_address = ('127.0.0.1', 0)
    HTTPD = HTTPServer(server_address, OauthRequestHandler)
    THREAD = threading.Thread(target=HTTPD.serve_forever)
    THREAD.daemon = True
    THREAD.start()
    return HTTPD.server_address

def shutdown_server():
    """
    Shutdown the web server
    """
    global THREAD
    global HTTPD
    del THREAD
    del HTTPD

