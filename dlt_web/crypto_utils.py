# =============================================================================
# crypto_utils.py
# RSA cryptographic primitives implemented from scratch.
# No third-party sign/verify functions used.
# INTE2627 Assignment 2 - DLT Inventory Management System
# =============================================================================

import hashlib
import math


# ---------------------------------------------------------------------------
# Modular Arithmetic Helpers
# ---------------------------------------------------------------------------

def mod_inverse(e, phi):
    """
    Compute the modular inverse of e mod phi using the Extended Euclidean Algorithm.
    Returns d such that (e * d) % phi == 1.
    """
    # Extended Euclidean Algorithm
    old_r, r = e, phi
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    if old_r != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({e}, {phi}) = {old_r}")
    return old_s % phi


def mod_exp(base, exp, mod):
    """
    Fast modular exponentiation using Python's built-in pow with three arguments.
    Equivalent to (base ** exp) % mod but efficient for large numbers.
    """
    return pow(base, exp, mod)


# ---------------------------------------------------------------------------
# RSA Key Derivation
# ---------------------------------------------------------------------------

def derive_rsa_keys(p, q, e):
    """
    Given RSA primes p, q and public exponent e, derive:
      - n   : modulus
      - phi : Euler's totient = (p-1)(q-1)
      - d   : private exponent (modular inverse of e mod phi)

    Returns a dict with keys: p, q, e, n, phi, d
    """
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


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_message(message: str) -> int:
    """
    SHA-256 hash of a message string, returned as an integer.
    """
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return int(digest, 16)


def hash_message_mod(message: str, n: int) -> int:
    """
    SHA-256 hash reduced modulo n (for signing).
    """
    h = hash_message(message)
    return h % n


# ---------------------------------------------------------------------------
# RSA Digital Signature (from scratch)
# ---------------------------------------------------------------------------

def rsa_sign(message: str, d: int, n: int) -> int:
    """
    Sign a message using RSA private key (d, n).
    Signature S = H(message)^d mod n

    No third-party sign() function used.
    """
    h = hash_message_mod(message, n)
    signature = mod_exp(h, d, n)
    return signature


def rsa_verify(message: str, signature: int, e: int, n: int) -> bool:
    """
    Verify an RSA signature using public key (e, n).
    Recover H' = S^e mod n, compare with H(message) mod n.

    Returns True if valid, False otherwise.
    No third-party verify() function used.
    """
    h_expected = hash_message_mod(message, n)
    h_recovered = mod_exp(signature, e, n)
    return h_expected == h_recovered


# ---------------------------------------------------------------------------
# RSA Encryption / Decryption (for Task 3 secure delivery)
# ---------------------------------------------------------------------------

def rsa_encrypt(plaintext_int: int, e: int, n: int) -> int:
    """
    RSA encrypt an integer: C = M^e mod n
    """
    if plaintext_int >= n:
        raise ValueError("Plaintext integer must be less than modulus n.")
    return mod_exp(plaintext_int, e, n)


def rsa_decrypt(ciphertext_int: int, d: int, n: int) -> int:
    """
    RSA decrypt an integer: M = C^d mod n
    """
    return mod_exp(ciphertext_int, d, n)


def int_to_str(value: int) -> str:
    """Convert integer back to string via bytes."""
    byte_length = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_length, "big").decode("utf-8", errors="replace")


def str_to_int(text: str) -> int:
    """Convert a string to an integer via bytes."""
    return int.from_bytes(text.encode("utf-8"), "big")


def rsa_encrypt_text(plaintext: str, e: int, n: int) -> int:
    """
    Encrypt a text string using RSA public key (e, n).
    Converts string → integer → C = M^e mod n
    """
    m = str_to_int(plaintext)
    if m >= n:
        # Use hash as representative if message too large
        m = hash_message_mod(plaintext, n)
    return rsa_encrypt(m, e, n)


def rsa_decrypt_text(ciphertext: int, d: int, n: int, original_len_hint: int = None) -> str:
    """
    Decrypt RSA ciphertext to recover text string.
    C^d mod n → integer → string
    """
    m = rsa_decrypt(ciphertext, d, n)
    try:
        byte_length = (m.bit_length() + 7) // 8
        return m.to_bytes(byte_length, "big").decode("utf-8")
    except Exception:
        return str(m)
