
"""
SciTokens reference library.

This library provides the primitives necessary for working with SciTokens
authorization tokens.
"""

import time

import jwt
from . import urltools
import logging
from six import string_types

LOGGER = logging.getLogger("scitokens")
import uuid

import cryptography.hazmat.backends as backends
from .utils import keycache as KeyCache
from .utils import config
from .utils.errors import MissingIssuerException, InvalidTokenFormat, MissingKeyException, UnsupportedKeyException
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec

class SciToken(object):
    """
    An object representing the contents of a SciToken.
    """

    def __init__(self, key=None, algorithm=None, key_id=None, parent=None, claims=None):
        """
        Construct a SciToken object.

        :param key: Private key to sign the SciToken with.  It should be the PEM contents.
        :param algorithm: Private key algorithm to sign the SciToken with. Default: RS256
        :param str key_id: A string representing the Key ID that is used at the issuer
        :param parent: Parent SciToken that will be chained
        """

        if claims is not None:
            raise NotImplementedError()

        self._key = key
        derived_alg = None
        if key:
            derived_alg = self._derive_algorithm(key)

        # Make sure we support the key algorithm
        if key and not algorithm and not derived_alg:
            # We don't know the key algorithm
            raise UnsupportedKeyException("Key was given for SciToken, but algorithm was not "
                                          "passed to SciToken creation and it cannot be derived "
                                          "from the provided key")
        elif derived_alg and not algorithm:
            self._key_alg = derived_alg
        elif derived_alg and algorithm and derived_alg != algorithm:
            error_str = ("Key provided reports algorithm type: {0}, ".format(derived_alg) +
                         "while scitoken creation argument was {0}".format(algorithm))
            raise UnsupportedKeyException(error_str)
        elif key and algorithm:
            self._key_alg = algorithm
        else:
            # If key is not specified, and neither is algorithm
            self._key_alg = algorithm if algorithm is not None else config.get('default_alg')

        if self._key_alg not in ["RS256", "ES256"]:
            raise UnsupportedKeyException()
        self._key_id = key_id
        self._parent = parent
        self._claims = {}
        self._verified_claims = {}
        self.insecure = False
        self._serialized_token = None

    @staticmethod
    def _derive_algorithm(key):
        """
        Derive the algorithm type from the PEM contents of the key

        returns: Key algorithm if known, otherwise None
        """

        if isinstance(key, rsa.RSAPrivateKey):
            return "RS256"
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            if key.curve.name == "secp256r1":
                return "ES256"

        # If it gets here, we don't know what type of key
        return None


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
        
        if 'jti' not in payload:
            # Create a jti from a uuid
            payload['jti'] = str(uuid.uuid4())
            self._claims['jti'] = payload['jti']

        if self._key_id != None:
            encoded = jwt.encode(payload, self._key, algorithm = self._key_alg, headers={'kid': self._key_id})
        else:
            encoded = jwt.encode(payload, self._key, algorithm = self._key_alg)
        self._serialized_token = encoded

        # Move claims over to verified claims
        self._verified_claims.update(self._claims)
        self._claims = {}
        
        global LOGGER
        LOGGER.info("Signed Token: {0}".format(str(payload)))

        # Encode the returned string for backwards compatibility.
        # Previous versions of PyJWT returned bytes
        return str.encode(encoded)

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

    def __getitem__(self, claim):
        """
        Access the value corresponding to a particular claim; will
        return claims from both the verified and unverified claims.

        If a claim is not present, then a KeyError is thrown.
        """
        if claim in self._claims:
            return self._claims[claim]
        if claim in self._verified_claims:
            return self._verified_claims[claim]
        raise KeyError(claim)
    
    def __contains__(self, claim):
        """
        Check if the claim exists in the SciToken
        """
        if claim in self._claims:
            return True
        if claim in self._verified_claims:
            return True
        return False

    def __delitem__(self, claim):
        """
        Delete the claim from the SciToken
        """
        deleted = False
        if claim in self._claims:
            del self._claims[claim]
            deleted = True
        if claim in self._verified_claims:
            del self._verified_claims[claim]
            deleted = True
        
        if deleted:
            return
        else:
            raise KeyError(claim)

    def get(self, claim, default=None, verified_only=False):
        """
        Return the value associated with a claim, returning the
        default if the claim is not present.  If `verified_only` is
        True, then a claim is returned only if it is in the verified claims
        """
        if verified_only:
            return self._verified_claims.get(claim, default)
        return self._claims.get(claim, self._verified_claims.get(claim, default))

    def clone_chain(self):
        """
        Return a new, empty SciToken
        """
        raise NotImplementedError()

    def _deserialize_key(self, key_serialized, unverified_headers):
        """
        Given a serialized key and a set of UNVERIFIED headers, return
        a corresponding private key object.
        """

    @staticmethod
    def deserialize(serialized_token, audience=None, require_key=False, insecure=False, public_key=None):
        """
        Given a serialized SciToken, load it into a SciTokens object.

        Verifies the claims pass the current set of validation scripts.
        
        :param str serialized_token: The serialized token.
        :param str audience: The audience URI that this principle is claiming.  Default: None
        :param bool require_key: When True, require the key
        :param bool insecure: When True, allow insecure methods to verify the issuer,
                              including allowing "localhost" issuer (useful in testing).  Default=False
        :param str public_key: A PEM formatted public key string to be used to validate the token
        """

        if require_key is not False:
            raise NotImplementedError()

        if isinstance(serialized_token, bytes):
            serialized_token = serialized_token.decode('utf8')
        info = serialized_token.split(".")

        if len(info) != 3 and len(info) != 4: # header, format, signature[, key]
            raise InvalidTokenFormat("Serialized token is not a readable format.")

        if (len(info) != 4) and require_key:
            raise MissingKeyException("No key present in serialized token")

        serialized_jwt = info[0] + "." + info[1] + "." + info[2]

        unverified_headers = jwt.get_unverified_header(serialized_jwt)
        unverified_payload = jwt.decode(serialized_jwt, verify=False, algorithms=['RS256', 'ES256'],
                                        options={"verify_signature": False})
        
        # Get the public key from the issuer
        keycache = KeyCache.KeyCache().getinstance()
        if public_key == None:
            issuer_public_key = keycache.getkeyinfo(unverified_payload['iss'],
                                key_id=unverified_headers['kid'] if 'kid' in unverified_headers else None,
                                insecure=insecure)
        else:
            issuer_public_key = load_pem_public_key(public_key, backend=backends.default_backend())
        
        if audience:
            claims = jwt.decode(serialized_token, issuer_public_key, audience = audience, algorithms=['RS256', 'ES256'])
        else:
            claims = jwt.decode(serialized_token, issuer_public_key, algorithms=['RS256', 'ES256'])
        # Do we have the private key?
        if len(info) == 4:
            to_return = SciToken(key = key)
        else:
            to_return = SciToken()
            
        to_return._verified_claims = claims
        to_return._serialized_token = serialized_token
        return to_return


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
                if "ver" not in token or token["ver"] != "scitoken:2.0":
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

class InvalidPathError(EnforcementError):
    """
    An invalid test path was provided to the Enforcer object.

    Test paths must be absolute paths (start with '/')
    """

class InvalidAuthorizationResource(EnforcementError):
    """
    A scope was encountered with an invalid authorization.

    Examples include:
       - Authorizations that require paths (read, write) but none
         were included.
       - Scopes that include relative paths (read:~/foo)
    """

class Enforcer(object):

    """
    Enforce SciTokens-specific validation logic.

    Allows one to test if a given token has a particular authorization.

    This class is NOT thread safe; a separate object is needed for every thread.
    """

    _authz_requiring_path = set(["read", "write"])

    # An array of versions of scitokens that we understand and can enforce
    _versions_understood = [ 1, "scitoken:2.0" ]

    def __init__(self, issuer, audience=None):
        self._issuer = issuer
        self.last_failure = None
        if not self._issuer:
            raise EnforcementError("Issuer must be specified.")
        self._audience = audience
        self._test_access = False
        self._test_authz = None
        self._test_path = None
        self._token_scopes = set()
        self._now = 0
        self._validator = Validator()
        self._validator.add_validator("exp", self._validate_exp)
        self._validator.add_validator("nbf", self._validate_nbf)
        self._validator.add_validator("iss", self._validate_iss)
        self._validator.add_validator("iat", self._validate_iat)
        self._validator.add_validator("aud", self._validate_aud)
        self._validator.add_validator("scp", self._validate_scp)
        self._validator.add_validator("scope", self._validate_scope)
        self._validator.add_validator("jti", self._validate_jti)
        self._validator.add_validator("sub", self._validate_sub)
        self._validator.add_validator("ver", self._validate_ver)
        self._validator.add_validator("opt", self._validate_opt)

    def _reset_state(self):
        """
        Reset the internal state variables of the Enforcer object.  Automatically
        invoked each time the Enforcer is used to test or generate_acls
        """
        self._test_authz = None
        self._test_path = None
        self._test_access = False
        self._token_scopes = set()
        self._now = time.time()
        self.last_failure = None

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
        self._reset_state()
        self._test_access = True

        critical_claims = set(["scope"])
        # Check for the older "scp" attribute
        if 'scope' not in token and 'scp' in token:
            critical_claims = set(["scp"])
        
        # In scitokens 2.0, some claims are required
        if 'ver' in token and token['ver'] == "scitoken:2.0":
            critical_claims.update(['aud', 'ver'])

        if not path and (authz in self._authz_requiring_path):
            raise InvalidPathError("Enforcer provided with an empty path.")
        if path and not path.startswith("/"):
            raise InvalidPathError("Enforcer was given an invalid relative path to test; absolute path required.")

        self._test_path = path
        self._test_authz = authz
        self.last_failure = None
        try:
            self._validator.validate(token, critical_claims=critical_claims)
        except ValidationFailure as validation_failure:
            self.last_failure = str(validation_failure)
            return False
        return True

    def generate_acls(self, token):
        """
        Given a SciToken object and the expected issuer, return the valid ACLs.
        """
        self._reset_state()

        critical_claims = set(["scope"])
        # Check for the older "scp" attribute
        if 'scope' not in token and 'scp' in token:
            critical_claims = set(["scp"])

        try:
            self._validator.validate(token, critical_claims=critical_claims)
        except ValidationFailure as verify_fail:
            self.last_failure = str(verify_fail)
            raise
        return list(self._token_scopes)

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

    def _validate_aud(self, value):
        if not self._audience:
            return False
        elif self._audience == "ANY":
            return False
        elif value == "ANY":
            return True
        elif isinstance(self._audience, list):
            return value in self._audience
        return value == self._audience

    def _validate_ver(self, value):
        if value in self._versions_understood:
            return True
        else:
            return False

    @classmethod
    def _validate_opt(self, value):
        """
        Opt is optional information.  We don't know what's in there, so just
        return true.
        """
        del value
        return True

    @classmethod
    def _validate_sub(self, value):
        """
        SUB, or subject, should always pass.  It's mostly used for identifying
        a tokens origin.
        """
        # Fix for unused argument
        del value
        return True

    @classmethod
    def _validate_jti(self, value):
        """
        JTI, or json token id, should always pass.  It's mostly used for logging
        and auditing.
        """
        global LOGGER
        LOGGER.info("Validating SciToken with jti: {0}".format(value))
        return True

    def _check_scope(self, scope):
        """
        Given a scope, make sure it contains a resource
        for scope types that require resources.

        Returns a tuple of the (authz, path).  If path is
        not in the scope (and is not required to be explicitly inside
        the scope), it will default to '/'.
        """
        info = scope.split(":", 1)
        authz = info[0]
        if authz in self._authz_requiring_path and (len(info) == 1):
            raise InvalidAuthorizationResource("Token contains an authorization requiring a resource"
                                               "(path), but no path is present")
        if len(info) == 2:
            path = info[1]
            if not path.startswith("/"):
                raise InvalidAuthorizationResource("Token contains a relative path in scope")
            norm_path = urltools.normalize_path(path)
        else:
            norm_path = '/'
        return (authz, norm_path)

    def _validate_scp(self, value):
        if not isinstance(value, list):
            value = [value]
        if self._test_access:
            if not self._test_path:
                norm_requested_path = '/'
            else:
                norm_requested_path = urltools.normalize_path(self._test_path)
            for scope in value:
                authz, norm_path = self._check_scope(scope)
                if (self._test_authz == authz) and norm_requested_path.startswith(norm_path):
                    return True
            return False
        else:
            for scope in value:
                authz, norm_path = self._check_scope(scope)
                self._token_scopes.add((authz, norm_path))
            return True

    def _validate_scope(self, value):
        if not isinstance(value, string_types):
            raise InvalidAuthorizationResource("Scope is invalid.  Must be a space separated string")
        if self._test_access:
            if not self._test_path:
                norm_requested_path = '/'
            else:
                norm_requested_path = urltools.normalize_path(self._test_path)
            # Split on spaces
            for scope in value.split(" "):
                authz, norm_path = self._check_scope(scope)
                if (self._test_authz == authz) and norm_requested_path.startswith(norm_path):
                    return True
            return False
        else:
            # Split on spaces
            for scope in value.split(" "):
                authz, norm_path = self._check_scope(scope)
                self._token_scopes.add((authz, norm_path))
            return True

