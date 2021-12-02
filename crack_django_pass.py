#!/usr/bin/env python
"""
Django Password Hash:

pbkdf2_sha256$2000$xDb4PWMWoQengkNyzh1IU3jGkZWK+BKManvkeJPunVQ=

    >>> import hashlib
    >>> import base64
    >>> base64.b64encode(hashlib.pbkdf2_hmac('sha256', b'abc', b'good_salt', 2000))
    b'xDb4PWMWoQengkNyzh1IU3jGkZWK+BKManvkeJPunVQ='
"""
import base64
import hashlib
import sys

HELP_FLAGS = {'-h', '--help'}

if 3 > len(sys.argv) or set(sys.argv) & HELP_FLAGS:
    print('Usage:', sys.argv[0], 'PASSWORD_HASH', 'SECRET_KEY', 'DICT_FILE')
    sys.exit(0)

password_hash, secret_key, dict_file = sys.argv[1:]

# pbkdf2_sha256$10000$Bt...
algo, iter_count, password_hash = password_hash.split('$', 2)
password_hash = base64.b64decode(password_hash)
with open(dict_file) as f:
    for i, line in enumerate(f, 1):
        print(f'\riter: {i}', end='')
        password = line.rstrip()
        if not password:
            continue
        password_hash1 = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            secret_key.encode(),
            int(iter_count),
        )
        if password_hash == password_hash1:
            print()
            print("Password:", password)
            break
