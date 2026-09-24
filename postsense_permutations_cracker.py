#!/usr/bin/env python3
"""
Try every arrangement of a set of digits as the AES passphrase for the
OrangeCyberdefense level-6 blob, and stop when the decrypted text matches
the challenge's md5 check.

    python3 try_key_perms.py                # uses the digits below (4,3,2,8,7)
    python3 try_key_perms.py 4 3 2 8 7      # or pass your own digits

Dependency (one of):
    pip install cryptography      # preferred
    pip install pycryptodome      # fallback
"""

import base64
import hashlib
import itertools
import sys

# --- Challenge constants -----------------------------------------------------
ENCRYPTED_TEXT = "U2FsdGVkX1+S2mYClIFYkP2Xnk+MPGvowb/5arp4OqwK47Zc1GFWkzgVeK36ApiQ"
TARGET_MD5 = "3528b6fc9dd348938c9acdec61d06834"
DIGITS = ["4", "3", "2", "8", "7"]        # default digit set


def evp_bytes_to_key(password, salt, key_len, iv_len):
    """OpenSSL EVP_BytesToKey with MD5, 1 iteration (CryptoJS default)."""
    data = block = b""
    while len(data) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        data += block
    return data[:key_len], data[key_len:key_len + iv_len]


def aes_cbc_decrypt(key, iv, ciphertext):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(ciphertext) + d.finalize()
    except ImportError:
        try:
            from Crypto.Cipher import AES  # pycryptodome
        except ImportError:
            sys.exit("Install a crypto lib:  pip install cryptography  (or pycryptodome)")
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)


def try_key(passphrase):
    """Return plaintext if md5(plaintext) == target, else None."""
    raw = base64.b64decode(ENCRYPTED_TEXT)
    salt, ciphertext = raw[8:16], raw[16:]
    key, iv = evp_bytes_to_key(passphrase.encode(), salt, 32, 16)
    pt = aes_cbc_decrypt(key, iv, ciphertext)
    if pt and 1 <= pt[-1] <= 16:            # strip PKCS7 padding
        pt = pt[:-pt[-1]]
    try:
        text = pt.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if hashlib.md5(text.encode()).hexdigest() == TARGET_MD5 else None


def main():
    digits = sys.argv[1:] if len(sys.argv) > 1 else DIGITS
    perms = ["".join(p) for p in itertools.permutations(digits)]
    perms = list(dict.fromkeys(perms))      # de-duplicate (repeated digits)
    print(f"Trying {len(perms)} arrangements of {digits} ...\n")

    for i, cand in enumerate(perms, 1):
        result = try_key(cand)
        if result is not None:
            print(f"[{i}/{len(perms)}]  MATCH!")
            print(f"  key        : {cand}")
            print(f"  decrypted  : {result}")
            print(f"  next level : level7-{result}.html")
            return
    print("No arrangement matched the target md5.")


if __name__ == "__main__":
    main()
