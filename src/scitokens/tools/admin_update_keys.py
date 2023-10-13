from scitokens.utils.keycache import KeyCache

def main():
    # TODO: Make this work
    keycache = KeyCache()
    res = keycache.update_all_tokens()
    
    for i in res:
        print(i)

if __name__ == "__main__":
    main()
