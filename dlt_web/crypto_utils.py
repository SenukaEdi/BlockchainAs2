import hashlib
import math


# Finds the modular inverse needed for the RSA private key
# This is used to calculate d from e and phi

def mod_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    if old_r != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({e}, {phi}) = {old_r}")
    return old_s % phi


# Handles modular exponentiation for RSA calculations
# This is used instead of doing base ** exp directly because the numbers can be very large

def mod_exp(base, exp, mod):
    return pow(base, exp, mod)


# Creates the RSA public and private key values from p, q and e

def derive_rsa_keys(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return {
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "d": d,
    }


# Converts a message into a SHA-256 hash integer

def hash_message(message: str) -> int:
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return int(digest, 16)


# Reduces the hash so it fits within the RSA modulus

def hash_message_mod(message: str, n: int) -> int:
    h = hash_message(message)
    return h % n


# Signs a message using the RSA private key

def rsa_sign(message: str, d: int, n: int) -> int:
    h = hash_message_mod(message, n)
    signature = mod_exp(h, d, n)
    return signature


# Verifies the RSA signature using the public key

def rsa_verify(message: str, signature: int, e: int, n: int) -> bool:
    h_expected = hash_message_mod(message, n)
    h_recovered = mod_exp(signature, e, n)
    return h_expected == h_recovered


# Encrypts an integer using RSA

def rsa_encrypt(plaintext_int: int, e: int, n: int) -> int:
    if plaintext_int >= n:
        raise ValueError("Plaintext integer must be less than modulus n.")
    return mod_exp(plaintext_int, e, n)


# Decrypts an integer using RSA

def rsa_decrypt(ciphertext_int: int, d: int, n: int) -> int:
    return mod_exp(ciphertext_int, d, n)


# Converts an integer back into text

def int_to_str(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_length, "big").decode("utf-8", errors="replace")


# Converts text into an integer so RSA can process it

def str_to_int(text: str) -> int:
    return int.from_bytes(text.encode("utf-8"), "big")


# Encrypts normal text by converting it into an integer first

def rsa_encrypt_text(plaintext: str, e: int, n: int) -> int:
    m = str_to_int(plaintext)
    if m >= n:
        m = hash_message_mod(plaintext, n)
    return rsa_encrypt(m, e, n)


# Decrypts RSA ciphertext and tries to convert it back into readable text

def rsa_decrypt_text(ciphertext: int, d: int, n: int, original_len_hint: int = None) -> str:
    m = rsa_decrypt(ciphertext, d, n)
    try:
        byte_length = (m.bit_length() + 7) // 8
        return m.to_bytes(byte_length, "big").decode("utf-8")
    except Exception:
        return str(m)
