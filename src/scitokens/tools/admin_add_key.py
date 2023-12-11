import argparse
from scitokens.utils.keycache import KeyCache

def add_args():
    """
    Generate the ArgumentParser object for the CLI.
    """
    parser = argparse.ArgumentParser(description='Remove a local cached token')
    parser.add_argument('issuer', help='issuer')
    parser.add_argument('key_id', help='key_id')
    parser.add_argument('-f', '--force', action='store_true', help='Force add')
    args = parser.parse_args()
    return args

def main():
    args = add_args()
    keycache = KeyCache()
    res = keycache.add_key(args.issuer, args.key_id, force_refresh=args.force)
    
    if res != None:
        print("Successfully added token with issuer = {} and key_id = {}!".format(args.issuer, args.key_id))
        print(res)
    else:
        print("Cannot add issuer = {} and key_id = {} !".format(args.issuer, args.key_id))

if __name__ == "__main__":
    main()
