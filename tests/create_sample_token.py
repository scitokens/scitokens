#!/usr/bin/python

"""
Create a sample scitoken, signed with elliptic curve cryptography, from a well-known private key.
"""

import jwt
import json
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.utils import int_to_bytes

def long_to_base64(data, size=None):
    """
    base64-encode a large integer.
    """
    return base64.urlsafe_b64encode(int_to_bytes(data, size)).strip(b'=')

def gen_jwk():
    """
    Return two JSON Web Keys corresponding to a public and private key
    in a keypair.
    """
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    numbers = private_key.private_numbers()
    private_jwk = {"kty": "EC", "crv": "P-256", "d": long_to_base64(numbers.private_value)}
    public_jwk = {"kty": "EC", "crv": "P-256", "x": long_to_base64(numbers.public_numbers.x),
                  "y": long_to_base64(numbers.public_numbers.y)}
    return public_jwk, private_jwk, private_key


def main():
    """
    Main method for testing tool for creating a sample SciToken.
    """

    with open("sample_ecdsa_keypair.pem", "r") as file_pointer:
        serialized_pair = file_pointer.read()

    loaded_public_key = serialization.load_pem_public_key(
        serialized_pair,
        backend=default_backend()
    )
    # Does the public key make sense?
    serialized_public = loaded_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("My public key:\n", serialized_public)

    loaded_private_key = serialization.load_pem_private_key(
        serialized_pair,
        password=None, # Hey, it's a sample file committed to disk...
        backend=default_backend()
    )
    # Echo out the private key:
    serialized_private = loaded_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("My private key:\n", serialized_private)

    public_jwk, private_jwk, child_private_key = gen_jwk()

    print("Instance JWK keypair:", public_jwk, private_jwk)

    # Ok, now generate a token and verify it.
    token_encoded = jwt.encode({"read": "/ligo"}, serialized_private, algorithm="ES256",
        headers={"x5u": "https://vo.example.com/JWS", "cwk": public_jwk})
    #child_token_encoded = jwt.encode({"read": "/ligo/brian"}, serialized_child_private, algorithm="ES256",
    #                                 headers={"pwt": pwt})
    signature = token_encoded.split(".")[-1]

    #numbers = loaded_private_key.private_numbers()

    flattened = {}
    flattened['payload'] = jwt.decode(token_encoded)
    flattened['protected'] = jwt.get_unverified_header(token_encoded)
    flattened['signature'] = token_encoded.split(".")[-1]

    print("My encoded token:\n", token_encoded)

    print("Plain-text token:\n", flattened)

    header = jwt.get_unverified_header(token_encoded)
    print("Non-validated header:\n", header)

    token_decoded = jwt.decode(token_encoded, serialized_public, algorithm="ES256")
    print("Validated token:\n", token_decoded)

    # Let's generate the child token
    pwt = {"payload": token_decoded, "protected": header, "signature": signature}

    serialized_child_private = child_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    child_token_encoded = jwt.encode({"read": "/ligo/brian"}, serialized_child_private, algorithm="ES256",
                                     headers={"pwt": pwt})
    flattened = {}
    flattened['payload'] = jwt.decode(child_token_encoded)
    flattened['protected'] = jwt.get_unverified_header(child_token_encoded)
    flattened['signature'] = child_token_encoded.split(".")[-1]
    flattened['key'] = private_jwk

    print("Child token, encoded:\n", child_token_encoded)
    print("Child token with key:\n", child_token_encoded+"."+base64.urlsafe_b64encode(json.dumps(private_jwk)))
    print("Child token headers:\n", jwt.get_unverified_header(child_token_encoded))
    print("Child token, flattened:\n", flattened)

if __name__ == '__main__':
    main()

