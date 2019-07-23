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

if password is None:
    print("You must specify a password in the environment variable PASSWORD")
    os.exit()

salt = os.urandom(16)
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)

message = {
    "salt" : base64.urlsafe_b64encode(salt).decode('utf-8')
    }

if sys.argv[1] is None:
    print("You must specify a filename to encrypt on the command line")
    os.exit()
else:
    filename = sys.argv[1]

with open(filename, "rb") as plaintext_file:
    message["ciphertext"] = f.encrypt(plaintext_file.read()).decode('utf-8')

with open(filename + ".encrypted", "w") as ciphertext_file:
    json.dump(message, ciphertext_file)
