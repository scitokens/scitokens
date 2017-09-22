"""
Utilities for the SciTokens library
"""
import cryptography.utils
import base64

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

def string_from_long(data):
    """
    Create a base64 encoded string for an integer
    """
    return base64.urlsafe_b64encode(cryptography.utils.int_to_bytes(data)).decode('ascii')


def bytes_from_long(data):
    """
    Create a base64 encoded bytes for an integer
    """
    return base64.urlsafe_b64encode(cryptography.utils.int_to_bytes(data))
