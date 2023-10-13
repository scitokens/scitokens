import argparse
from scitokens.utils.keycache import KeyCache

def add_args():
    """
    Generate the ArgumentParser object for the CLI.
    """
    parser = argparse.ArgumentParser(description='Remove a local cached token')
    parser.add_argument('issuer', help='issuer')
    parser.add_argument('key_id', help='key_id')
    args = parser.parse_args()
    return args

def main():
    args = add_args()
    
    keycache = KeyCache()
    res = keycache.remove_token(args.issuer, args.key_id)
    
    if res == True:
        print("Successfully deleted token with issuer = {} and key_id = {}!".format(args.issuer, args.key_id))
    else:
        print("Token with issuer = {} and key_id = {} does NOT exist!".format(args.issuer, args.key_id))

if __name__ == "__main__":
    main()
