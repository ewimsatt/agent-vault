"""Cryptographic operations using pyrage (age encryption)."""

from __future__ import annotations

from pyrage import decrypt, x25519


def load_identity(key_path: str) -> x25519.Identity:
    """Load an age x25519 identity (private key) from a file.

    The file should contain a line starting with AGE-SECRET-KEY-.
    """
    with open(key_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("AGE-SECRET-KEY-"):
                return x25519.Identity.from_str(line)
    raise ValueError(f"No age secret key found in {key_path}")


def load_identity_from_str(key_str: str) -> x25519.Identity:
    """Load an age x25519 identity from a string."""
    for line in key_str.splitlines():
        line = line.strip()
        if line.startswith("AGE-SECRET-KEY-"):
            return x25519.Identity.from_str(line)
    raise ValueError("No age secret key found in provided string")


def decrypt_secret(ciphertext: bytes, identity: x25519.Identity) -> str:
    """Decrypt an age-encrypted secret and return the plaintext string."""
    plaintext_bytes = decrypt(ciphertext, [identity])
    return plaintext_bytes.decode("utf-8")
