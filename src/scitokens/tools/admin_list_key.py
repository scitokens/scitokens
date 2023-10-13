from scitokens.utils.keycache import KeyCache

def main():
    # TODO: Make this work
    keycache = KeyCache()
    res = keycache.list_token(keycache._get_cache_file())
    
    header = ["issuer", "expiration", "key_id", "keydata", "next_update"]
    
    print("{:<30} | {:<25} | {:<40} | {:<20} | {}".format(header[0], header[1], header[2], header[3], header[4]))
    print("-" * 150)
    for record in res:
        print("{:<30} | {:<25} | {:<40} | {:<20} | {}".format(record[0], record[1], record[2], record[3][:20], record[4]))

if __name__ == "__main__":
    main()