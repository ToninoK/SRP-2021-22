# Lab 3 - Message Authentication and Integrity

## Environment setup

1. We create a python virtual environment for the project
    
    `virtualenv venv`
    
2. We get inside the virtual environment with `source ./venv/bin/activate` and install the cryptography package which we will need
    
    `pip install cryptography`
    

## First Challenge

We need to implement message integrity security using the right Message Authentication Code algorithm. We will use `hmac` from the pythons' `cryptography` library.

1. We create a text file within our folder. This text file will represent the data whose integrity we want to protect.
2. We load the contents of the file to our app

```python
# Reading from a file
 with open(filename, "rb") as file:
     content = file.read()
```

3. Now we will write the function to generate the MAC code of our data

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature
```

4. Also we need to write the function to check the validity of the MAC for the given message

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True
```

5. We can then try and modify the contents of the file and see that the validity check will result in `False`
6. The complete code looks like this

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

def run():
    KEY = b'me secret ke'
    
    # Reading from a file
    with open('secret.txt', "rb") as file:
        content = file.read()
    should_succeed(KEY, content)
    should_fail(KEY, content)
    

def should_succeed(KEY, message):
    sig = generate_MAC(KEY, message)
    print(f'This should be True: {verify_MAC(KEY, sig, message)}')

def should_fail(KEY, message):
    sig = generate_MAC(KEY, message)
    message = message + b'some more message'
    print(f'This should be False: {verify_MAC(KEY, sig, message)}')

if __name__ == "__main__":
    run()
```

## Second Challenge

In this challenge we want to determine the correct sequence of the messages and also check the integrity of the messages.

1. We download the files representing the messages and their MAC-s from the local server and place them inside our folder in which we will code

```python
wget.exe -r -nH -np --reject "index.html*" http://a507-server.local/challenges/<prezime_ime>/
```

2. To check the MAC we also need the key. The given key is `"<surname_name>".encode()` 
3. First we will create a function in which we can pass the filename and get the full relative path to the file

```python
def get_folder(name):
    return f"./challenges/kastelan_tonino/mac_challenge/{name}"
```

4. We will also reuse the functions from the first challenge to generate and verify the MAC

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True
```

5. Now we will create a for loop to iterate over all of the files and read them and their signatures (MAC values)

```python
for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"

        with open(get_folder(msg_filename), 'rb') as file:
            message = file.read()
        
        with open(get_folder(sig_filename), 'rb') as file:
            sig = file.read()
```

6. Also each loop we will verify if the MAC is valid or not

```python
for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"

        with open(get_folder(msg_filename), 'rb') as file:
            message = file.read()
        
        with open(get_folder(sig_filename), 'rb') as file:
            sig = file.read()
        
        is_authentic = verify_MAC(KEY, sig, msg)
        print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

7. Additionally to check if the order is correct we will store the current order in a list in this format: `(timestamp, current_position)`
8. To do this we will create a function to extract the timestamp from the message

```python
def get_tstamp(message):
    return datetime.strptime(message.decode()[-17:-1], "%Y-%m-%dT%H:%M")
```

9. Now we can go back to the loop and store the current order

```python
order = []
for ctr in range(1, 11):
    msg_filename = f"order_{ctr}.txt"
    sig_filename = f"order_{ctr}.sig"

    with open(get_folder(msg_filename), 'rb') as file:
        message = file.read()
    
    with open(get_folder(sig_filename), 'rb') as file:
        sig = file.read()
    
    is_authentic = verify_MAC(KEY, sig, msg)
    print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')

    tstamp = get_tstamp(message)
    order.append((tstamp, ctr))
```

10. We now need to sort the order by the timestamp and check if the sorted order is same as the unsorted order. If they are not the same we will print the corrected order.

```python
correct_order = sorted(order, key=lambda x: x[0])
correct_order_idxs = [item[1] for item in correct_order]

if correct_order_idx != [i for i in range(1, 11)]:
    print(f"Order incorrect.")
    print(f"The correct order of messages is: {[item[1] for item in correct_order]}")
```

11. All together the code will look like this

```python
from datetime import datetime

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

KEY = "kastelan_tonino".encode()

def get_folder(name):
    return f"./challenges/kastelan_tonino/mac_challenge/{name}"

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

def get_tstamp(message):
    return datetime.strptime(message.decode()[-17:-1], "%Y-%m-%dT%H:%M")

def run():
    order = []
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"

        with open(get_folder(msg_filename), 'rb') as file:
            message = file.read()
        
        with open(get_folder(sig_filename), 'rb') as file:
            sig = file.read()
        
        is_authentic = verify_MAC(KEY, sig, msg)
        print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')

        tstamp = get_tstamp(message)
        order.append((tstamp, ctr))

    correct_order = sorted(order, key=lambda x: x[0])
    correct_order_idxs = [item[1] for item in correct_order]

    if correct_order_idx != [i for i in range(1, 11)]:
        print(f"Order incorrect.")
        print(f"The correct order of messages is: {[item[1] for item in correct_order]}")
    

if __name__ == "__main__":
    run()
```