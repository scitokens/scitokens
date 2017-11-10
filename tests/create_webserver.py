"""
Utility to create a simple webserver that will answer oauth .well-known
required requests.  This is so we can test the HTTP requesting part of issuers.
"""

import threading
import json
import base64
try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer

import cryptography.utils

# For use in the HTTP Serve test class
#test_kid = ""
TEST_N = 0
TEST_E = 0
TEST_ID = ""
HTTPD = None
THREAD = None



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
        global httpd

        # Make sure the User-Agent is SciTokens*
        user_agent = self.headers.get('User-Agent')
        if not user_agent.startswith("SciTokens"):
            self.send_response(404)
            return
        self._set_headers()
        to_write = ""
        if self.path == "/.well-known/openid-configuration":
            to_write = json.dumps({"jwks_uri": "http://localhost:{}/oauth2/certs".format(httpd.server_address[1])})
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


def start_server(test_n, test_e, test_id):
    """
    Man this is ugly.  But you have to set global variables because it's
    impossible to send arguments to the HTTPServer, since you pas the HTTPServer
    an type, not an instance.
    
    :param long int test_n: N for an RSA key
    :param long int test_e: E for an RSA key
    :param str test_id: Key ID for the test key
    """
    global TEST_N
    global TEST_E
    global TEST_ID
    global THREAD
    global HTTPD
    
    TEST_N = test_n
    TEST_E = test_e
    TEST_ID = test_id
    
    server_address = ('', 0)
    HTTPD = HTTPServer(server_address, OauthRequestHandler)
    THREAD = threading.Thread(target=httpd.serve_forever)
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
    
    