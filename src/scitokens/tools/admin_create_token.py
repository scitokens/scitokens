
"""
Generate a SciToken from command-line inputs (and a local signing key).
"""

import argparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import scitokens


def add_args():
    """
    Generate the ArgumentParser object for the CLI.
    """
    parser = argparse.ArgumentParser(description='Create a new SciToken')
    parser.add_argument('claims', metavar='C', type=str, nargs='+',
                        help='Claims in the format key=value')
    parser.add_argument('--keyfile',
                        help='Location of the private key file')
    parser.add_argument('--key_id', help='The string key identifier')
    parser.add_argument('--issuer', help="Issuer for the token")
    parser.add_argument('--lifetime', help="Lifetime of the token, in seconds from now. Default: 1200 seconds (20 minutes)",
                        type=int, default=1200)

    args = parser.parse_args()
    return args


def main():
    """
    Given a set of command line parameters, generate a corresponding SciToken.
    """
    args = add_args()

    with open(args.keyfile, "r") as file_pointer:
        private_key_contents = file_pointer.read()

    loaded_private_key = serialization.load_pem_private_key(
        private_key_contents.encode(),
        password=None, # Hey, it's a sample file committed to disk...
        backend=default_backend()
    )

    token = scitokens.SciToken(key=loaded_private_key, key_id=args.key_id)

    for claim in args.claims:
        (key, value) = claim.split('=', 1)
        token.update_claims({key: value})

    serialized_token = token.serialize(issuer=args.issuer, lifetime=args.lifetime)
    print(serialized_token.decode())


if __name__ == "__main__":
    main()
