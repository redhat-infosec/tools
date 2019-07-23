#!/bin/env python3

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import sys
import os
import base64
import json

password = bytes(os.environ["PASSWORD"], "utf-8")

if sys.argv[1] is None:
    print("You must specify a filename to encrypt on the command line")
    os.exit()
else:
    filename = sys.argv[1]

if password is None:
    print("You must specify a password in the environment variable PASSWORD")
    os.exit()

with open(filename, "rb") as ciphertext_file:
    message = json.load(ciphertext_file)

salt = base64.urlsafe_b64decode(message["salt"])

kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)


with open(filename.replace(".encrypted", ".decrypted"), "wb") as plaintext_file:
    plaintext_file.write(f.decrypt(message["ciphertext"].encode('utf-8')))
    
