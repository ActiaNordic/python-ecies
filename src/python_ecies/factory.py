# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""This module contains factory for preconfigured ECIES objects."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from . import format, key_derivation, symmetric
from .ecies import ECIES


def get_default_hkdf_aesgcm_binary() -> ECIES:
    """Returns a ECIES object with HKDF, AES-GCM(256) and binary output."""
    return ECIES(
        key_deriver=key_derivation.HKDF(),
        encrypter=symmetric.AESGCMEncrypter(),
        output_format=format.BinaryOutput(),
    )


def get_sec1_concatkdf_aescbc_sha256_binary(aes_key_length: int = 32) -> ECIES:
    """Returns a ECIES object using a "standard" SECG SEC 1 confg with  Concat-KDF, AES-CBC(n)+HMAC and binary output.

    Args:
        aes_key_length: The key length to use for AES
    """
    return ECIES(
        key_deriver=key_derivation.ConcatKDF(),
        encrypter=symmetric.CipherHMACEncryptor(
            aes_key_length,
            cipher_algorithm=algorithms.AES,
            cipher_mode=modes.CBC,
            hmac_algorithm=hashes.SHA256(),
        ),
        output_format=format.BinaryOutput(),
    )
