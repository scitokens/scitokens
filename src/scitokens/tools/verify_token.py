"""
Verify a SciToken from command-line inputs.
"""

import argparse
import scitokens
from scitokens.utils.errors import InvalidTokenFormat
from scitokens.utils.errors import MissingIssuerException
from scitokens.utils.errors import MissingKeyException
from scitokens.utils.errors import NonHTTPSIssuer
from scitokens.utils.errors import SciTokensException
from scitokens.utils.errors import UnableToCreateCache
from scitokens.utils.errors import UnsupportedKeyException


def add_args():
    """
    Generate the ArgumentParser object for the CLI.
    """
    parser = argparse.ArgumentParser(description='Verify a new SciToken')
    parser.add_argument('token', type=str, nargs=1, help='The serialized string of SciToken')
    parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()
    return args


def main():
    """
    Given a serialized SciToken, verify it and return an error message in case of failure.
    """
    args = add_args()
    stoken = None
    try:
        stoken = scitokens.SciToken.deserialize(args.token[0])

        if args.verbose:
            print("Claims:")
            for claim in stoken.claims():
                print("{}".format(claim))

    except MissingKeyException:
        print("No private key is present.")
    except UnsupportedKeyException:
        print("The provided algorithm in the token is not the one supported by SciToken library (RS256, ES256).")
    except MissingIssuerException:
        print("Issuer not specific in claims or as argument.")
    except NonHTTPSIssuer:
        print("Issuer is not over HTTPS. RFC requires it to be over HTTPS.")
    except InvalidTokenFormat:
        print("Serialized token is not a readable format.")
    except UnableToCreateCache as utcce:
        print("Unable to create cache: {}".format(str(utcce)))
    except SciTokensException as scite:
        print("An error raised from SciTokens library while verifying the token: {}".format(str(scite)))
    except Exception as exc:
        print("An error occurred while verifying the token: {}".format(str(exc)))


if __name__ == "__main__":
    main()
