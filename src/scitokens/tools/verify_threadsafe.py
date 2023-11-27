import threading
import time
from scitokens.utils.keycache import KeyCache

def verify_job(issuer, key_id):
    keycache = KeyCache()
    res = keycache.add_key(issuer, key_id, False)
    print(res)

def main():
    threads = []
    arguments = [('https://demo.scitokens.org', 'key-rs256'), ('https://demo.scitokens.org', 'key-rs256')]
    for i in range(2000):
        thread = threading.Thread(target=verify_job, args=arguments[i%2])
        threads.append(thread)
        thread.start()
    
    for thread in threads:  # iterates over the threads
        thread.join()     
    
if __name__ == "__main__":
    main()

# import multiprocessing
# import threading
# import time
# from scitokens.utils.keycache import KeyCache

# def verify_job(issuer, key_id):
#     keycache = KeyCache()
#     time.sleep(1)
#     res = keycache.add_key(issuer, key_id, False)
#     time.sleep(1)
#     print(res)

# def task_thread1():
#     for i in range(5):
#         print(f"Thread 1 - Process {multiprocessing.current_process().name}: {i}")
#         time.sleep(1)

# def task_thread2():
#     for i in range(5):
#         print(f"Thread 2 - Process {multiprocessing.current_process().name}: {i}")
#         time.sleep(1)

# def process_function():
#     thread1 = threading.Thread(target=verify_job, args=('https://demo.scitokens.org', 'key-rs256'))
#     thread2 = threading.Thread(target=verify_job, args=('https://demo.scitokens.org', 'key-rs256'))

#     thread1.start()
#     thread2.start()

#     thread1.join()
#     thread2.join()

# if __name__ == "__main__":
#     process1 = multiprocessing.Process(target=process_function)
#     process2 = multiprocessing.Process(target=process_function)

#     process1.start()
#     process2.start()

#     process1.join()
#     process2.join()
