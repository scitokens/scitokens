from scitokens.utils.keycache import KeyCache

def main():
    # TODO: Make this work
    keycache = KeyCache()
    res = keycache.list_token()
    
    header = ["issuer", "expiration", "key_id", "keydata", "next_update"]
    
    print("{:<30} | {:<19} | {:<35} | {:<20} | {}".format(header[0], header[1], header[2], header[3], header[4]))
    print("-" * 135)
    for record in res:
        print("{:<30} | {:<19} | {:<35} | {:<20} | {}".format(record[0], record[1], record[2], record[3][:20], record[4]))

if __name__ == "__main__":
    main()
