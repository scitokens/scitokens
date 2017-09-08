
import base64
import urllib
import urlparse
import json

import jwt

import cryptography.utils
import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.backends as backends

def long_from_bytes(data):
    return cryptography.utils.int_from_bytes(decode_base64(data.encode("ascii")), 'big')
    
def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'='* (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

class MissingKeyException(Exception):
    pass

class UnsupportedKeyException(Exception):
    pass

class SciToken(object):

    def __init__(self, key=None, parent=None):
        """
        
        
        :param key: Private key to sign the SciToken with.  It should be the PEM contents.
        :param parent: Parent SciToken that will be chained
        """
    
        self._key = key
        self._parent = parent
        self._claims = {}

    def __init__(self, token):
        """ 
        When the token is all we have
        
        TODO: lots of verification of token input!
        
        :param token: base64 encoded token
        """
        
        # Split the token: header.payload.signature
        split_token = token.split('.')
        
        # Decode the header and payload from base64 to json
        header = json.loads(decode_base64(split_token[0]))
        payload = json.loads(decode_base64(split_token[1]))
        
        # Get the issuer of the token (is it in payload or header?)
        issuer = payload['iss']
        
        # TODO: whitelist of issuers that we trust?
        
        # Go to the issuer's website, and download the OAuth well known bits
        # https://tools.ietf.org/html/draft-ietf-oauth-discovery-07
        well_known_uri = "/.well-known/openid-configuration"
        meta_uri = urlparse.urljoin(issuer, well_known_uri)
        response = urllib.urlopen(meta_uri)
        data = json.loads(response.read())
        
        # Get the keys URL from the openid-configuration
        jwks_uri = data['jwks_uri']
        
        # Now, get the keys
        response = urllib.urlopen(jwks_uri)
        keys_data = json.loads(response.read())
        # Loop through each key, looking for the right key id
        public_key = ""
        for key in keys_data['keys']:
            if (key['kid'] == header['kid']):
                public_key_numbers = rsa.RSAPublicNumbers(
                    long_from_bytes(key['e']),
                    long_from_bytes(key['n'])
                )
                public_key = public_key_numbers.public_key(backends.default_backend())
                break
        
        
        claims = jwt.decode(token, public_key)
        

    def claims(self):
        """
        Return an iterator of (key, value) pairs of claims, starting
        with the claims from the first token in the chain.
        """
        if parent:
            for claim in self._parent.claims():
                yield claim
        for claim in self._claims:
            yield claim


    def verify(self):
        """
        Verify the claims of the in-memory token.

        Automatically called by deserialize.
        """
        raise NotImplementedError()

    def serialize(self, include_key=False):
        """
        Serialize the existing SciToken.
        """
        
        

    def update_claims(claims):
        """
        Add new claims to the token.
        
        :param claims: Dictionary of claims to add to the token
        """
        
        self._claims.update(claims)

    def clone_chain(self):
        """
        Return a new, empty SciToken 
        """

    def _deserialize_key(self, key_serialized, unverified_headers):
        """
        Given a serialized key and a set of UNVERIFIED headers, return
        a corresponding private key object.
        """

    def deserialize(self, serialized_token, require_key=True):
        """
        Given a serialized SciToken, load it into a SciTokens object.

        Verifies the claims pass the current set of validation scripts.
        """
        info = serialized_token.split(".")
        if len(info) != 4: # header, format, signature, key
            raise MissingKeyException("No key present in serialized token")

        key = info[-1]
        serialized_jwt = info[0] + "." + info[1] + "." + info[2]

        unverified_headers = jwt.get_unverified_headers(serialized_jwt)

        key_decoded = base64.urlsafe_b64decode(key)
        jwk_dict = json.loads(key_decoded)
        # TODO: Full range of keytypes and curves from JWK RFC.
        if (jwk_dict['kty'] != 'EC') or (jwt_dict['crv'] != 'P-256'):
            raise UnsupportedKeyException("SciToken signed with an unsupported key type")
        elif 'd' not in jwk_dict:
            raise UnsupportedKeyException("SciToken key does not contain private number.")

        if 'pwt' in unverified_headers:
            pwt = unverified_headers['pwt']
            st = SciToken.clone()
            st.deserialize(pwt, require_key=False)
            headers = pwt.headers()
            if 'cwk' not in headers:
                raise InvalidParentToken("Parent token MUST specify a child JWK.")
            # Validate the key type / curve matches.  TODO: what other headers to check?
            if (jwk_dict['kty'] != headers['kty']) or (jwk_dict['crv'] != headers['crv']):
                if 'x' not in jwk_dict:
                    if 'x' in headers:
                        jwk_dict['x'] = headers['x']
                    else:
                        MissingPublicKeyException("JWK public key is missing 'x'")
                elif jwk_dict['x'] != headers['x']:
                    raise UnsupportedKeyException("Parent SciToken specifies an incompatible child JWK")
                if 'y' not in jwk_dict:
                    if 'y' in headers:
                        jwk_dict['y'] = headers['y']
                    else:
                        MissingPublicKeyException("JWK public key is missing 'y'")
                elif jwk_dict['y'] != headers['y']:
                    raise UnsupportedKeyException("Parent SciToken specifies an incompatible child JWK")
        # TODO: Handle non-chained case.
        elif 'x5u' in unverified_headers:
            raise NotImplementedError("Non-chained verification is not implemented.")
        else:
            raise UnableToValidate("No token validation method available.")

        public_key_numbers = ec.EllipticCurvePublicNumbers(
               long_from_bytes(jwk_dict['x']),
               long_from_bytes(jwk_dict['y']),
               ec.SECP256R1
           )
        private_key_numbers = ec.EllipticCurvePrivateNumbers(
           long_from_bytes(jwk_dict['d']),
           public_key_numbers
        )
        private_key = private_key_numbers.private_key(backends.default_backend())
        public_key  = public_key_numbers.public_key(backends.default_backend())

        # TODO: check that public and private key match?

        claims = jwt.decode(serialized_token, public_key, algorithm="EC256")


