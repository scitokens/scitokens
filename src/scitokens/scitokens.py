
"""
SciTokens reference library.

This library provides the primitives necessary for working with SciTokens
authorization tokens.
"""

import base64

try:
    import urllib.request as request
except ImportError:
    import urllib2 as request
    
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
import json
import time

import jwt
import urltools
import pkg_resources  # part of setuptools
try:
    PKG_VERSION = pkg_resources.require("scitokens")[0].version
except pkg_resources.DistributionNotFound as error:
    # During testing, scitokens won't be installed, so requiring it will fail
    # Instead, fake it
    PKG_VERSION = '1.0.0'

import cryptography.utils
import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.backends as backends

def long_from_bytes(data):
    """
    Return an integer from base64-encoded string.

    :param data: UTF-8 string containing base64-encoded data.
    :returns: Corresponding decoded integer.
    """
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
    """
    No private key is present.

    The SciToken required the use of a public or private key, but
    it was not provided by the caller.
    """
    pass

class UnsupportedKeyException(Exception):
    """
    Key is present but is of an unsupported format.

    A public or private key was provided to the SciToken, but
    could not be handled by this library.
    """
    pass
    
class MissingIssuerException(Exception):
    """
    Missing the issuer in the SciToken, unable to verify token
    """
    pass
    
class NonHTTPSIssuer(Exception):
    """
    Non HTTPs issuer, as required by draft-ietf-oauth-discovery-07
    https://tools.ietf.org/html/draft-ietf-oauth-discovery-07
    """
    pass
    
class InvalidTokenFormat(Exception):
    """
    Encoded token has an invalid format.
    """


class SciToken(object):
    """
    An object representing the contents of a SciToken.
    """

    def __init__(self, key=None, key_id=None, parent=None, claims=None):
        """
        Construct a SciToken object.
        
        :param key: Private key to sign the SciToken with.  It should be the PEM contents.
        :param str key_id: A string representing the Key ID that is used at the issuer
        :param parent: Parent SciToken that will be chained
        """
        
        if claims is not None:
            raise NotImplementedError()
    
        self._key = key
        self._key_id = key_id
        self._parent = parent
        self._claims = {}
        self._verified_claims = {}
        self.insecure = False
        self._serialized_token = None

    def claims(self):
        """
        Return an iterator of (key, value) pairs of claims, starting
        with the claims from the first token in the chain.
        """
        if self._parent:
            for claim, value in self._parent.claims():
                yield claim, value
        for claim, value in self._verified_claims.items():
            yield claim, value
        for claim, value in self._claims.items():
            yield claim, value


    def verify(self):
        """
        Verify the claims of the in-memory token.

        Automatically called by deserialize.
        """
        raise NotImplementedError()


    def serialize(self, include_key=False, issuer=None, lifetime=600):
        """
        Serialize the existing SciToken.
        
        :param bool include_key: When true, include the public key to the serialized token.  Default=False
        :param str issuer: A string indicating the issuer for the token.  It should be an HTTPS address,
                           as specified in https://tools.ietf.org/html/draft-ietf-oauth-discovery-07
        :param int lifetime: Number of seconds that the token should be valid
        :return str: base64 encoded token
        """
        
        if include_key is not False:
            raise NotImplementedError()
        
        if self._key == None:
            raise MissingKeyException("Unable to serialize, missing private key")
        
        # Issuer needs to be available, otherwise throw an error
        if issuer == None and 'iss' not in self._claims:
            raise MissingIssuerException("Issuer not specific in claims or as argument")
        
        if not issuer:
            issuer = self._claims['iss']
        
        # Set the issue and expiration time of the token
        issue_time = int(time.time())
        exp_time = int(issue_time + lifetime)
        
        # Add to validated and other claims
        payload = dict(self._verified_claims)
        payload.update(self._claims)

        
        # Anything below will override what is in the claims
        payload.update({
            "iss": issuer,
            "exp": exp_time,
            "iat": issue_time,
            "nbf": issue_time
        })
        
        if self._key_id != None:
            encoded = jwt.encode(payload, self._key, algorithm = "RS256", headers={'kid': self._key_id})
        else:
            encoded = jwt.encode(payload, self._key, algorithm = "RS256")
        self._serialized_token = encoded
        
        # Move claims over to verified claims
        self._verified_claims.update(self._claims)
        self._claims = {}
        
        return encoded
        
        

    def update_claims(self, claims):
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
    def _get_issuer_publickey(header, payload, insecure=False):
        
        # Get the issuer
        issuer = payload['iss']
        
        # Set the user agent so Cloudflare isn't mad at us
        headers={'User-Agent': 'SciTokens/{}'.format(PKG_VERSION)}
        
        # Go to the issuer's website, and download the OAuth well known bits
        # https://tools.ietf.org/html/draft-ietf-oauth-discovery-07
        well_known_uri = ".well-known/openid-configuration"
        if not issuer.endswith("/"):
            issuer = issuer + "/"
        parsed_url = urlparse.urlparse(issuer)
        updated_url = urlparse.urljoin(parsed_url.path, well_known_uri)
        parsed_url_list = list(parsed_url)
        parsed_url_list[2] = updated_url
        meta_uri = urlparse.urlunparse(parsed_url_list)
        
        # Make sure the protocol is https
        if not insecure:
            parsed_url = urlparse.urlparse(meta_uri)
            if parsed_url.scheme != "https":
                raise NonHTTPSIssuer("Issuer is not over HTTPS.  RFC requires it to be over HTTPS")
        response = request.urlopen(request.Request(meta_uri, headers=headers))
        data = json.loads(response.read().decode('utf-8'))
        
        # Get the keys URL from the openid-configuration
        jwks_uri = data['jwks_uri']
        
        # Now, get the keys
        if not insecure:
            parsed_url = urlparse.urlparse(jwks_uri)
            if parsed_url.scheme != "https":
                raise NonHTTPSIssuer("jwks_uri is not over HTTPS, insecure!")
        response = request.urlopen(request.Request(jwks_uri, headers=headers))
        keys_data = json.loads(response.read().decode('utf-8'))
        # Loop through each key, looking for the right key id
        public_key = ""
        raw_key = None
        
        # If there is no kid in the header, then just take the first key?
        if 'kid' not in header:
            if len(keys_data['keys']) != 1:
                raise NotImplementedError("No kid in header, but multiple keys in "
                                          "response from certs server.  Don't know which key to use!")
            else:
                raw_key = keys_data['keys'][0]
        else:
            # Find the right key
            for key in keys_data['keys']:
                if key['kid'] == header['kid']:
                    raw_key = key
                    break

        if raw_key == None:
            raise MissingKeyException("Unable to find key at issuer {}".format(jwks_uri))

        if raw_key['kty'] == "RSA":
            public_key_numbers = rsa.RSAPublicNumbers(
                long_from_bytes(raw_key['e']),
                long_from_bytes(raw_key['n'])
            )
            public_key = public_key_numbers.public_key(backends.default_backend())
        elif raw_key['kty'] == 'EC':
            public_key_numbers = ec.EllipticCurvePublicNumbers(
                   long_from_bytes(raw_key['x']),
                   long_from_bytes(raw_key['y']),
                   ec.SECP256R1
               )
            public_key = public_key_numbers.public_key(backends.default_backend())
        else:
            raise UnsupportedKeyException("SciToken signed with an unsupported key type")
        
        return public_key
        
        
    @staticmethod
    def deserialize(serialized_token, require_key=False, insecure=False):
        """
        Given a serialized SciToken, load it into a SciTokens object.

        Verifies the claims pass the current set of validation scripts.
        
        :param str serialized_token: The serialized token.
        :param bool require_key: When True, require the key
        :param bool insecure: When True, allow insecure methods to verify the issuer,
                              including allowing "localhost" issuer (useful in testing).  Default=False
        """
        
        if require_key is not False:
            raise NotImplementedError()
        
        info = serialized_token.decode('utf8').split(".")
        
        if len(info) != 3 and len(info) != 4: # header, format, signature[, key]
            raise MissingKeyException("No key present in serialized token")

        serialized_jwt = info[0] + "." + info[1] + "." + info[2]

        unverified_headers = jwt.get_unverified_header(serialized_jwt)
        unverified_payload = jwt.decode(serialized_jwt, verify=False)
        
        # Get the public key from the issuer
        issuer_public_key = SciToken._get_issuer_publickey(unverified_headers, unverified_payload, insecure=insecure)
        
        claims = jwt.decode(serialized_token, issuer_public_key)
        # Do we have the private key?
        if len(info) == 4:
            to_return = SciToken(key = key)
        else:
            to_return = SciToken()
            
        to_return._verified_claims = claims
        to_return._serialized_token = serialized_token
        return to_return
        
        
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


class MissingClaims(ValidationFailure):
    """
    Validation failed because one or more claim marked as critical is missing
    from the token.
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

    def validate(self, token, critical_claims=None):
        """
        Validate the claims of a token.

        This will iterate through all claims in the given :class:`SciToken`
        and determine whether all claims a valid, given the current set of
        validators.

        If ``critical_claims`` is specified, then validation will fail if one
        or more claim in this list is not present in the token.

        This will throw an exception if the token is invalid and return ``True``
        if the token is valid.
        """
        if critical_claims:
            critical_claims = set(critical_claims)
        else:
            critical_claims = set()
        for claim, value in token.claims():
            if claim in critical_claims:
                critical_claims.remove(claim)
            validator_list = self._callbacks.setdefault(claim, [])
            if not validator_list:
                raise NoRegisteredValidator("No validator was registered to handle encountered claim '%s'" % claim)
            for validator in validator_list:
                if not validator(value):
                    raise ClaimInvalid("Validator rejected value of '%s' for claim '%s'" % (value, claim))
        if len(critical_claims):
            raise MissingClaims("Validation failed because the following claims are missing: %s" % \
                                ", ".join(critical_claims))
        return True

    def __call__(self, token):
        return self.validate(token)


class EnforcementError(Exception):
    """
    A generic error during the enforcement of a SciToken.
    """

class Enforcer(object):

    """
    Enforce SciTokens-specific validation logic.

    Allows one to test if a given token has a particular authorization.

    This class is NOT thread safe; a separate object is needed for every thread.
    """

    _authz_requiring_path = set(["read", "write"])

    def __init__(self, issuer, site=None, audience=None):
        self._issuer = issuer
        self.last_failure = None
        if not self._issuer:
            raise EnforcementError("Issuer must be specified.")
        self._now = 0
        self._test_authz = None
        self._test_path = None
        self._audience = audience
        self._site = site
        self._validator = Validator()
        self._validator.add_validator("exp", self._validate_exp)
        self._validator.add_validator("nbf", self._validate_nbf)
        self._validator.add_validator("iss", self._validate_iss)
        self._validator.add_validator("iat", self._validate_iat)
        self._validator.add_validator("site", self._validate_site)
        self._validator.add_validator("aud", self._validate_aud)
        self._validator.add_validator("path", self._validate_path)
        self._validator.add_validator("authz", self._validate_authz)

    def add_validator(self, claim, validator):
        """
        Add a user-defined validator in addition to the default enforcer logic.
        """
        self._validator.add_validator(claim, validator)

    def test(self, token, authz, path=None):
        """
        Test whether a given token has the requested permission within the
        current enforcer context.
        """
        critical_claims = set(["authz"])
        if authz in self._authz_requiring_path:
            critical_claims.add("path")
        self._now = time.time()
        self._test_path = path
        self._test_authz = authz
        try:
            self._validator.validate(token, critical_claims=critical_claims)
        except ValidationFailure as vf:
            self.last_failure = str(vf)
            return False
        return True

    def _validate_exp(self, value):
        exp = float(value)
        return exp >= self._now

    def _validate_nbf(self, value):
        nbf = float(value)
        return nbf < self._now

    def _validate_iss(self, value):
        return self._issuer == value

    def _validate_iat(self, value):
        return float(value) < self._now

    def _validate_site(self, value):
        if not self._site:
            return False
        return value == self._site

    def _validate_aud(self, value):
        if not self._audience:
            return False
        return value == self._audience

    def _validate_path(self, value):
        if not isinstance(value, list):
            value = [value]
        norm_requested_path = urltools.normalize(self._test_path)
        for path in value:
            norm_path = urltools.normalize(path)
            if norm_requested_path.startswith(norm_path):
                return True
        return False

    def _validate_authz(self, value):
        if not isinstance(value, list):
            value = [value]
        for authz in value:
            if self._test_authz == authz:
                return True
        return False

