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
import multiprocessing as mp
import sys

HELP_FLAGS = {'-h', '--help'}


COLORS = {
    'black': 30,
    'red': 31,
    'green': 32,
    'yellow': 33,
    'blue': 34,
    'purple': 35,
    'cyan': 36,
    'white': 37,
}


def colorize(color, text):
    return f'\033[0;{COLORS[color]}m{text}\033[0m'


def check_password(args):
    password, secret_key, iters, ref_hash = args
    pass_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        secret_key.encode(),
        iters,
    )
    if pass_hash == ref_hash:
        return password
    return False


def main():
    if 3 > len(sys.argv) or set(sys.argv) & HELP_FLAGS:
        print('Usage:', sys.argv[0], 'PASS_HASH', 'SECRET_KEY', 'DICT_FILE')
        sys.exit(0)

    pass_hash, secret_key, dict_file = sys.argv[1:]
    with open(dict_file) as f:
        candidates = f.read().splitlines()

    algo, iters, pass_hash = pass_hash.split('$', 2)
    assert algo == 'pbkdf2_sha256'
    iters = int(iters)
    pass_hash = base64.b64decode(pass_hash)

    pool = mp.Pool(mp.cpu_count() * 2)
    # count = 0

    for number, result in enumerate(
        pool.imap_unordered(
            check_password,
            (
                (candidate, secret_key, iters, pass_hash)
                for candidate in candidates
            ),
        ),
        1,
    ):
        # print(f'\r{(count := count + 1)}', end='')
        progress_value = round(number / len(candidates) * 100)
        print(f'\rCandidates checked: {progress_value}%', end='')

        if result == False:
            continue

        pool.terminate()
        print('\r\033[0K' + colorize('green', f'[FOUND] {result}'))
        return

    print('\r\033[0K' + colorize('red', '[!] Nothing found :-('))


if __name__ == '__main__':
    main()
