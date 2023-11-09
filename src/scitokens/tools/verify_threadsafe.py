import threading
import time
from scitokens.utils.keycache import KeyCache

def verify_job(issuer, key_id):
    keycache = KeyCache()
    res = keycache.add_key(issuer, key_id, False)
    print(res)

def main():
    threads = []
    arguments = [('minh', 'minh'), ('vy', 'vy')]
    for i in range(20):
        thread = threading.Thread(target=verify_job, args=arguments[i%2])
        threads.append(thread)
        thread.start()
    
    for thread in threads:  # iterates over the threads
        thread.join()     
    
if __name__ == "__main__":
    main()


