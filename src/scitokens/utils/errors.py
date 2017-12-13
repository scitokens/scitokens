"""
Error and Exceptions in the SciTokens library
"""

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
    pass

class UnableToCreateCache(Exception):
    """
    Unable to make the KeyCache
    """
