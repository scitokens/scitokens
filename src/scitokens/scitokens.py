
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
        

    def claims(self):
        """
        Return an iterator of (key, value) pairs of claims, starting
        with the claims from the first token in the chain.
        """
        if self._parent:
            for claim, value in self._parent.claims():
                yield claim, value
        for claim, value in self._claims.items():
            yield claim, value


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

    def __setitem__(self, claim, value):
        """
        Assign a new claim to the token.
        """
        self._claims[claim] = value

    def clone_chain(self):
        """
        Return a new, empty SciToken 
        """

    def _deserialize_key(self, key_serialized, unverified_headers):
        """
        Given a serialized key and a set of UNVERIFIED headers, return
        a corresponding private key object.
        """
        
    @staticmethod
    def _get_issuer_publickey(header, payload):
        
        # Get the issuer
        issuer = payload['iss']
        
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
                if key['kty'] == "RSA":
                    public_key_numbers = rsa.RSAPublicNumbers(
                        long_from_bytes(key['e']),
                        long_from_bytes(key['n'])
                    )
                    public_key = public_key_numbers.public_key(backends.default_backend())
                    break
                elif key['kty'] == 'EC':
                    public_key_numbers = ec.EllipticCurvePublicNumbers(
                           long_from_bytes(key['x']),
                           long_from_bytes(key['y']),
                           ec.SECP256R1
                       )
                else:
                    raise UnsupportedKeyException("SciToken signed with an unsupported key type")
        
        return public_key
        
        
    @staticmethod
    def deserialize(serialized_token, require_key=True):
        """
        Given a serialized SciToken, load it into a SciTokens object.

        Verifies the claims pass the current set of validation scripts.
        """
        info = serialized_token.split(".")
        if len(info) != 3 and len(info) != 4: # header, format, signature[, key]
            raise MissingKeyException("No key present in serialized token")

        key = info[-1]
        serialized_jwt = info[0] + "." + info[1] + "." + info[2]

        unverified_headers = jwt.get_unverified_header(serialized_jwt)
        unverified_payload = json.loads(decode_base64(info[1]))
        
        # Get the public key from the issuer
        issuer_public_key = SciToken._get_issuer_publickey(unverified_headers, unverified_payload)
        
        claims = jwt.decode(serialized_token, issuer_public_key)
        print claims
        return
        
        # Clean up all of the below

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


class ValidationFailure(Exception):
    """
    Validation of a token was attempted but failed for an unknown reason.
    """


class NoRegisteredValidator(ValidationFailure):
    """
    The Validator object attempted validation of a token, but encountered a
    claim with no registered validator.
    """


class ClaimInvalid(ValidationFailure):
    """
    The Validator object attempted validation of a given claim, but one of the
    callbacks marked the claim as invalid.
    """

class Validator(object):

    """
    Validate the contents of a SciToken.

    Given a SciToken, validate the contents of its claims.  Unlike verification,
    which checks that the token is correctly signed, validation provides an easy-to-use
    interface that ensures the claims in the token are understood by the user.
    """


    def __init__(self):
        self._callbacks = {}

    def add_validator(self, claim, validate_op):
        """
        Add a validation callback for a given claim.  When the given ``claim``
        encountered in a token, ``validate_op`` object will be called with the
        following signature::

        >>> validate_op(value)

        where ``value`` is the value of the token's claim converted to a python
        object.

        The validator should return ``True`` if the value is acceptable and ``False``
        otherwise.
        """
        validator_list = self._callbacks.setdefault(claim, [])
        validator_list.append(validate_op)

    def validate(self, token):
        """
        Validate the claims of a token.

        This will iterate through all claims in the given :class:`SciToken`
        and determine whether all claims a valid, given the current set of
        validators.

        This will throw an exception if the token is invalid and return ``True``
        if the token is valid.
        """
        for claim, value in token.claims():
            validator_list = self._callbacks.setdefault(claim, [])
            if not validator_list:
                raise NoRegisteredValidator("No validator was registered to handle encountered claim '%s'" % claim)
            for validator in validator_list:
                if not validator(value):
                    raise ClaimInvalid("Validator rejected value of '%s' for claim '%s'" % (value, claim))
        return True

    def __call__(self, token):
        return self.validate(token)

