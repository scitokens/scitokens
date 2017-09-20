#!/usr/bin/env python

import argparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import scitokens

# Arguments:

def add_args():
    
    parser = argparse.ArgumentParser(description='Create a new SciToken')
    parser.add_argument('claims', metavar='C', type=str, nargs='+',
                        help='Claims in the format key=value')
    parser.add_argument('--keyfile', 
                        help='Location of the private key file')
    parser.add_argument('--key_id', help='The string key identifier')
    parser.add_argument('--issuer', help="Issuer for the token")

    args = parser.parse_args()
    return args


def main():
    args = add_args()
    print(args)

    with open(args.keyfile, "r") as fp:
        private_key_contents = fp.read()

    loaded_private_key = serialization.load_pem_private_key(
        private_key_contents,
        password=None, # Hey, it's a sample file committed to disk...
        backend=default_backend()
    )

    token = scitokens.SciToken(key=loaded_private_key, key_id=args.key_id)
    
    for claim in args.claims:
        (key, value) = claim.split('=', 1)
        token.update_claims({key: value})
    
    serialized_token = token.serialize(issuer=args.issuer)
    print(serialized_token)


if __name__ == "__main__":
    main()
