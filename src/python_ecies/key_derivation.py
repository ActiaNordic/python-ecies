# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""This module contains key derivation functions."""

from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import concatkdf, hkdf, x963kdf
from typing_extensions import override

from .common import KeyDerivationOperation

__all__ = ["HKDF"]


class HKDF(KeyDerivationOperation):
    """Key derivation using the HKDF algorithm with a settable hash."""

    def __init__(
        self,
        hash_algo: Optional[hashes.HashAlgorithm] = None,
        salt: Optional[bytes] = None,
        info: Optional[bytes] = None,
    ) -> None:
        """Initialize a new HKDF key derivation object.

        Args:
            hash_algo: Hash algorithm to use for the HMAC part. If none is specified, default of
                       SHA256 will be used.
            salt: Extra salt to use when computing the derived key
            info: Extra info to feed into the HKDF
        """
        self._hash_algo = hash_algo if hash_algo else hashes.SHA256()
        self._salt = salt
        self._info = info

    @override
    def __call__(self, key_material: bytes, key_length: int) -> bytes:
        return hkdf.HKDF(self._hash_algo, length=key_length, salt=self._salt, info=self._info).derive(
            key_material=key_material
        )

    @override
    @property
    def identity(self) -> str:
        return f"hkdf({self._hash_algo.name})"


class X963KDF(KeyDerivationOperation):
    """Key derivation using the X9.63 KDF."""

    def __init__(
        self,
        hash_algo: Optional[hashes.HashAlgorithm] = None,
        info: Optional[bytes] = None,
    ) -> None:
        """Initialize a new X9.63-KDF key derivation object.

        Args:
            hash_algo: Hash algorithm to use for the HMAC part. If none is specified, default of
                       SHA256 will be used.
            info: Extra info to feed into the X9.63 KDF
        """
        self._hash_algo = hash_algo if hash_algo else hashes.SHA256()
        self._info = info

    @override
    def __call__(self, key_material: bytes, key_length: int) -> bytes:
        return x963kdf.X963KDF(self._hash_algo, length=key_length, sharedinfo=self._info).derive(
            key_material=key_material
        )

    @override
    @property
    def identity(self) -> str:
        return f"x963kdf({self._hash_algo.name})"


class ConcatKDF(KeyDerivationOperation):
    """Key derivation using the NIST SP 800-56Ar3 KDF."""

    def __init__(
        self,
        hash_algo: Optional[hashes.HashAlgorithm] = None,
        info: Optional[bytes] = None,
    ) -> None:
        """Initialize a new NIST SP 800-56Ar3 ConcatKDF key derivation object.

        Args:
            hash_algo: Hash algorithm to use for the HMAC part. If none is specified, default of
                       SHA256 will be used.
            info: Extra info to feed into the X9.63 KDF
        """
        self._hash_algo = hash_algo if hash_algo else hashes.SHA256()
        self._info = info

    @override
    def __call__(self, key_material: bytes, key_length: int) -> bytes:
        return concatkdf.ConcatKDFHash(self._hash_algo, length=key_length, otherinfo=self._info).derive(
            key_material=key_material
        )

    @override
    @property
    def identity(self) -> str:
        return f"concatkdf({self._hash_algo.name})"
