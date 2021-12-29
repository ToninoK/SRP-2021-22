# Lab 4 - Password Hashing

## Leftover from Lab 3 - Public Key Cryptography

Of the two given images we need to find the authentic one. We have the public key necessary to check this.

1. First lets’ write some code to load the public key:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

PUBLIC_KEY_FILE="public.pem"

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY
```

1. Now we need to add some function to somehow verify the signature:

```python
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

PUBLIC_KEY_FILE="public.pem"

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
```

1. Lastly a simple way to run all of this and test it:

```python
def run():
    with open('image_1.sig', 'rb') as file:
        sig_1 = file.read()
    with open('image_2.sig', 'rb') as file:
        sig_2 = file.read()
    with open('image_1.png', 'rb') as file:
        msg_1 = file.read()
    with open('image_2.png', 'rb') as file:
        msg_2 = file.read()
    
    print(f"Signature 1 is {'valid' if verify_signature_rsa(sig_1, msg_1) else 'invalid'}")
    print(f"Signature 2 is {'valid' if verify_signature_rsa(sig_2, msg_2) else 'invalid'}")
```

1. All together the code comes to this:

```python
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

PUBLIC_KEY_FILE="public.pem"

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True

def run():
    with open('image_1.sig', 'rb') as file:
        sig_1 = file.read()
    with open('image_2.sig', 'rb') as file:
        sig_2 = file.read()
    with open('image_1.png', 'rb') as file:
        msg_1 = file.read()
    with open('image_2.png', 'rb') as file:
        msg_2 = file.read()
    
    print(f"Signature 1 is {'valid' if verify_signature_rsa(sig_1, msg_1) else 'invalid'}")
    print(f"Signature 2 is {'valid' if verify_signature_rsa(sig_2, msg_2) else 'invalid'}")

if __name__ == "__main__":
    run()
```

## Start of Lab 4

1. First we setup the code environment by installing the requirements from the given `requirements.txt` with pip:

```bash
pip install -r requirements.txt
```

1. After this we will use the code given below to test out the speed of specific cryptographic hash functions of different types

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

1. We can now modify and play with the `TESTS` variable adding different tests we want to time. We specifically ran these tests:

```python
TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "Linux crypt 5 000",
            "service": lambda: linux_hash(password, measure=True, rounds=5000)
        },
        {
            "name": "Linux crypt 10 000",
            "service": lambda: linux_hash(password, measure=True, rounds=10000)
        },
        {
            "name": "Linux crypt 50 000",
            "service": lambda: linux_hash(password, measure=True, rounds=50000)
        },
        {
            "name": "Linux crypt 100 000",
            "service": lambda: linux_hash(password, measure=True, rounds=100000)
        },
    ]
```

Here we saw that increasing rounds drastically changes the execution time of the functions.

1. Last thing we took a look at was the `linux_hash` function and how it works depending on the salt. We firstly ran the code without a specific salt, so the function generated its own. Then we used a fixed salt. We noticed that with a fixed salt result is the same. To see this run the next code inside the last `if`:

```python
print(linux_hash(password))
print(linux_hash(password))
print(linux_hash(password), salt=FIXED_SALT)
print(linux_hash(password), salt=FIXED_SALT)
```