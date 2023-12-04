import argparse
from scitokens.utils.keycache import KeyCache

def add_args():
    """
    Generate the ArgumentParser object for the CLI.
    """
    parser = argparse.ArgumentParser(description='Update all tokens in the cache')
    parser.add_argument('-f', '--force', action='store_true', help='Force refresh all tokens')
    args = parser.parse_args()
    return args

def main():
    args = add_args()
    keycache = KeyCache()
    res = keycache.update_all_keys(force_refresh=args.force)
    for i in res:
        print(i)

if __name__ == "__main__":
    main()


