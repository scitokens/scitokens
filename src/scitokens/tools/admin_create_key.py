
"""
Create the oauth2 certs file from a given private or public key.  The resulting format
should be something like:

{
    "keys": [
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "ca78d4d8011b0442025c05885efba3f83764b436961d5cf09cec408ac6c675f2",
            "kty": "RSA",
            "n": "07llFSVsW8cXjy0kG2jHYm084QaSEZcrtw02fHbo30gxgdp6h-maIwNkj_xB-N29kUAe0McoJaL_P4P29rZfh_gh06f9fu60g_GPfVXBuKI61k1FfseaHLtwk2l20WOYHnx92v69UeylJEyNVVYNEhPUHEZdWWqzOjMUIC7XBnQ_GRiGu_9y7JFY-sIS28Iv36r7HKxv1k_i_B5LpOcZ0wUVxmk2WsflgSLg94iUAs8EU2ugI0ea8HG8hP6lPvcWdz4xIQlPYaovrLV_PgTOxVouye979BGIiWgkC7v0hYn5TV7xoIu_3ytm-MKFfas3MZ0cnGBWjlBqVNf-wNguSQ==",
            "use": "sig"
        }
    ]
}

"""

import sys
import cryptography.utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import base64
import binascii
import json
import argparse
from scitokens.utils import string_from_long, bytes_from_long




def add_args():
    """
    Generate the ArgumentParser object for the CLI.
    """
    parser = argparse.ArgumentParser(description='Format a given public key (or create one from a private key) in the format needed for OAuth2 issuer')
    
    # Mutual exclude.  Either give the private keyfile, or public, but not both, and at least 1
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--private-keyfile',
                        help='Location of the unencrypted private key file')
    group.add_argument('--public-keyfile',
                        help='Location of a public key file')
    group.add_argument('--create-keys',
                        help='Create the private and public keys',
                        action='store_true')
    
    parser.add_argument('--jwks-public', help='Print the JWK formatted public key', action='store_true')
    parser.add_argument('--jwks-private', help='Print the JWK formatted private key', action='store_true')
    parser.add_argument('--pem-private', help='Print the PEM formatted private key', action='store_true')
    parser.add_argument('--pem-public', help='Print the PEM formatted public key', action='store_true')
    parser.add_argument('--ec', help='Use eliptical curve cryptograph', action='store_true')

    args = parser.parse_args()
    return args


def main():
    """
    Given a set of command line parameters, generate a corresponding oauth2 certs file.
    """
    args = add_args()
    private_key = None
    public_key = None
    
    
    
    if args.private_keyfile:
        with open(args.private_keyfile, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            public_key = private_key.public_key()
    elif args.public_keyfile:
        # Check for conflicting arguments
        if args.jwks_private or args.pem_private:
            raise Exception("Only given public key on command line, cannot output private keys")
        
        with open(args.public_keyfile, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    elif args.create_keys:
        # Create the private key
        if args.ec:
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend()
            )
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        public_key = private_key.public_key()
    

    # Get the public numbers
    public_numbers = public_key.public_numbers()

    # Hash the public "n", and use it for the Key ID (kid)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    if args.ec:
        digest.update(bytes_from_long(public_numbers.x))
    else:
        digest.update(bytes_from_long(public_numbers.n))
    kid = binascii.hexlify(digest.finalize())

    # Shorten the kid to 4 characters
    kid = kid[:4]

    if args.jwks_public:
        if args.ec:
            jwk_public_key = {'keys': [
                {
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": string_from_long(public_numbers.x),
                    "y": string_from_long(public_numbers.y),
                    "kty": "EC",
                    "use": "sig",
                    "kid": kid.decode('utf-8')
                }
            ]}
        else:
            jwk_public_key = {'keys': [
                {
                    "alg": "RS256",
                    "n": string_from_long(public_numbers.n),
                    "e": string_from_long(public_numbers.e),
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid.decode('utf-8')
                }
            ]}
        print(json.dumps(jwk_public_key, sort_keys=True,
                        indent=4, separators=(',', ': ')))
    
    if args.jwks_private:
        private_numbers = private_key.private_numbers()
        
        if args.ec:
            jwk_private_key = {'keys': [
                {
                    'kty': 'EC',
                    "crv": "P-256",
                    'kid': kid.decode('utf-8'),
                    "x": string_from_long(private_numbers.public_numbers.x),
                    "y": string_from_long(private_numbers.public_numbers.y),
                    'd': string_from_long(private_numbers.private_value)
                }
            ]}
        else:
            jwk_private_key = {'keys': [
                {
                    'kty': 'RSA',
                    "alg":"RS256",
                    'kid': kid.decode('utf-8'),
                    "n": string_from_long(private_numbers.public_numbers.n),
                    "e": string_from_long(private_numbers.public_numbers.e),
                    'p': string_from_long(private_numbers.p),
                    'q': string_from_long(private_numbers.q),
                    'd': string_from_long(private_numbers.d),
                    'dp': string_from_long(private_numbers.dmp1),
                    'dq': string_from_long(private_numbers.dmq1),
                    'qi': string_from_long(private_numbers.iqmp),
                }
            ]}
        print(json.dumps(jwk_private_key, sort_keys=True,
                        indent=4, separators=(',', ': ')))
    
    if args.pem_private:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        for line in private_pem.splitlines():
            print(line.decode())
    
    if args.pem_public:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        for line in public_pem.splitlines():
            print(line.decode())


if __name__ == "__main__":
    main()
