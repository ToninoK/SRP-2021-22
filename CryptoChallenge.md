# Lab 2 - Crypto Challenge

We have a server with encrypted files uploaded on it. We need to find out our file by hashing our name and then decrypt the contents of the file.

## Environment setup

1. We create a python virtual environment for the project
    
    `virtualenv venv`
    
2. We get inside the virtual environment with `./venv/source/bin/activate` and install the cryptography package which we will need
    
    `pip install cryptography`
    

## Challenge Part 1 - Finding out our file

1. First we need to hash our name to find out the name of the file which matches us

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def hashy(input):
    if not isinstance(input, bytes):
        input = input.encode()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hashe = digest.finalize()

    return hashe.hex()

filename = hashy('kastelan_tonino') + ".encrypted"
print(filename)
```

1. Running the above code generates next hash: `a86133c01fc988ce4fb18862342fb87b9544f16beda65699a5428874a5721692.encrypted`
    
    It represents the name of the file we need to decrypt from the server.
    
2. We download the file so we can decrypt it

## Challenge Part 2 - File decryption

1. We know two things
    1. keys have a limited entropy of 22 bits → this is possible to brute force in a relatively short time especially applying parallelization
    2. the encrypted file is a .png image → this means we can check if the decryption was successful by checking if the headers of the file contain .png headers
2. We can create an infinite loop that will iterate through all of the 2^22 keys, each iteration checking the headers of the decrypted file. Furthermore we can speed this up by making the process parallel using pythons' `multiprocessing` module. The result will look something like this:

```python
import os
import base64

from cryptography.fernet import Fernet
from multiprocessing import Pool

class Colors:
    PINK = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[0m'

def run():
    ciphertext = ""
    with open('file.encrypted', 'rb') as file:
        ciphertext = file.read()
    total_keys = 2**22
    chunk_size = int(total_keys/os.cpu_count())
    with Pool() as pool:
        def found_key(event):
            print(f"{Colors.GREEN}Finished", flush=True)
            pool.terminate()

        index = 1
        for chunk_start_index in range(0, total_keys, chunk_size):
            pool.apply_async(
                brute,
                (
                    ciphertext, 
                    chunk_start_index,
                    chunk_size,
                    index,
                ),
                callback=found_key,
            )
            index += 1
        pool.close()
        pool.join()

def test_png(text):
    if text.startswith(b"\211PNG\r\n\032\n"):
        return True
    return False

def brute(ciphertext, start, size, index):
    process_id = os.getpid()
    print(f"{Colors.BLUE}[+]{Colors.WHITE} Process with pid {process_id} started (index: {index}) - Chunk: {start} - {start + size}")

    ctr = start    
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
        if not (ctr + 1) % 1000 and index == 3:
            print(f"{Colors.YELLOW}[*] [{index}]{Colors.WHITE} Keys tested: {ctr+1:,}", end="\r")

        try:
            
            data = Fernet(key).decrypt(ciphertext)
            if test_png(data[:32]):
                print(f"{Colors.GREEN}[{index}][+]{Colors.WHITE} Key found: {key}")
                with open('success.png', 'wb') as file:
                    file.write(data)
                break        

        except:
            pass

        if ctr == start + size + 1
            break
        ctr += 1

    print(f"{Colors.RED}Process {process_id} finished.")

if __name__ == "__main__":
    print(f"{Colors.PINK}Starting Attack...")
    run()
```

If the decryption was successful we should have a `success.png` in the folder we are running the program in.