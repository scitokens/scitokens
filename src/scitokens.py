
import base64

import jwt

import cryptography.utils
import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.backends as backends

def long_from_bytes(data):
    return cryptography.utils.int_from_bytes(base64.urlsafe_b64decode(data, 'big'))

class MissingKeyException(Exception):
    pass

class UnsupportedKeyException(Exception):
    pass

class SciToken(object):

    def __init__(self, key=None, parent=None):
        self._key = key
        self._parent = parent
        self._claims = {}


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
        """

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


