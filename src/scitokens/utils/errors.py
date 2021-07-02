"""
Error and Exceptions in the SciTokens library
"""


class SciTokensException(Exception):
    """
    Base class for exceptions in the SciTokens library
    """
    pass

class MissingKeyException(SciTokensException):
    """
    No private key is present.

    The SciToken required the use of a public or private key, but
    it was not provided by the caller.
    """
    pass

class UnsupportedKeyException(SciTokensException):
    """
    Key is present but is of an unsupported format.

    A public or private key was provided to the SciToken, but
    could not be handled by this library.
    """
    pass

class MissingIssuerException(SciTokensException):
    """
    Missing the issuer in the SciToken, unable to verify token
    """
    pass

class NonHTTPSIssuer(SciTokensException):
    """
    Non HTTPs issuer, as required by draft-ietf-oauth-discovery-07
    https://tools.ietf.org/html/draft-ietf-oauth-discovery-07
    """
    pass

class InvalidTokenFormat(SciTokensException):
    """
    Encoded token has an invalid format.
    """
    pass

class UnableToCreateCache(SciTokensException):
    """
    Unable to make the KeyCache
    """
