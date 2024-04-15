# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""This module defines symmetric encryption and authentication functions."""

import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, CipherAlgorithm, aead, modes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.hmac import HMAC
from typing_extensions import override

from .common import EncryptionResult, KeyDerivationOperation, SymmetricEncrypterAndAuthenticator

__all__ = ["AESGCMEncrypter", "ChaCha20Poly1305Encrypter", "CipherHMACEncryptor"]


class AESGCMEncrypter(SymmetricEncrypterAndAuthenticator):
    """Symmetric encryptor and authenticator using AES-GCM."""

    _key_length: int
    _nonce_length: int

    min_nonce_length = 12

    def __init__(self, key_length: int = 32, nonce_length: int = 16) -> None:
        """Initialize a new AES-GCM Encrypter object.

        Args:
            key_length: AES key length to use, in bytes (16, 24 or 32)
            nonce_length: Nonce/IV length to use, in bytes (at least 12)

        Raises:
            ValueError if key_length or nonce_length is invalid
        """
        if key_length not in (16, 24, 32):
            msg = "AES-GCM key must be 128, 192, or 256 bits."
            raise ValueError(msg)
        if nonce_length < self.min_nonce_length:
            msg = "AES-GCM needs at least 96 bits of IV"
            raise ValueError(msg)

        self._key_length = key_length
        self._nonce_length = nonce_length

    @override
    def encrypt(self, kd: KeyDerivationOperation, key_material: bytes, data: bytes) -> EncryptionResult:
        key = kd(key_material, self._key_length)

        nonce = secrets.token_bytes(self._nonce_length)
        aes_output = aead.AESGCM(key).encrypt(nonce=nonce, data=data, associated_data=None)

        tag_length = self.tag_length
        return EncryptionResult(encrypted_data=aes_output[:-tag_length], tag=aes_output[-tag_length:], nonce=nonce)

    @override
    def decrypt(self, kd: KeyDerivationOperation, key_material: bytes, encrypted_data: EncryptionResult) -> bytes:
        key = kd(key_material, self._key_length)

        return aead.AESGCM(key).decrypt(
            nonce=encrypted_data.nonce,
            data=encrypted_data.encrypted_data + encrypted_data.tag,
            associated_data=None,
        )

    @override
    @property
    def nonce_length(self) -> int:
        return self._nonce_length

    @override
    @property
    def tag_length(self) -> int:
        return 16

    @override
    @property
    def identity(self) -> str:
        return f"aesgcm({self._key_length*8},{self._nonce_length*8})"


class ChaCha20Poly1305Encrypter(SymmetricEncrypterAndAuthenticator):
    """Symmetric encryptor and authenticator using ChaCha20Poly1305.

    Fixed 32 byte (256 bit) key and 12 bytes (96 bit) nonce is used
    """

    @override
    def encrypt(self, kd: KeyDerivationOperation, key_material: bytes, data: bytes) -> EncryptionResult:
        key = kd(key_material, 32)

        nonce = secrets.token_bytes(12)
        chacha_output = aead.ChaCha20Poly1305(key).encrypt(nonce=nonce, data=data, associated_data=None)

        tag_length = self.tag_length
        return EncryptionResult(
            encrypted_data=chacha_output[:-tag_length], tag=chacha_output[-tag_length:], nonce=nonce
        )

    @override
    def decrypt(self, kd: KeyDerivationOperation, key_material: bytes, encrypted_data: EncryptionResult) -> bytes:
        key = kd(key_material, 32)

        return aead.ChaCha20Poly1305(key).decrypt(
            nonce=encrypted_data.nonce,
            data=encrypted_data.encrypted_data + encrypted_data.tag,
            associated_data=None,
        )

    @override
    @property
    def nonce_length(self) -> int:
        return 12

    @override
    @property
    def tag_length(self) -> int:
        return 16

    @override
    @property
    def identity(self) -> str:
        return "chacha20poly1305()"


class CipherHMACEncryptor(SymmetricEncrypterAndAuthenticator):
    """Symmetric encryptor and authenticator using symmetric cipher and a HMAC combined.

    The symmetric cipher algorithm and mode, and the HMAC hash function, can be customized on initialization.

    Example use could be:

    .. code-block:: python

        from cryptography.hazmat.primitives.ciphers.algorithms import (
            AES,
        )
        from cryptography.hazmat.primitives.ciphers.modes import (
            CBC,
        )
        from cryptography.hazmat.primitives.hashes import (
            SHA256,
        )

        encryptor = CipherHMACEncryptor(
            cipher_key_length=12,
            cipher_algorithm=AES,
            cipher_mode=CBC,
            hmac_algorithm=SHA256(),
        )
    """

    _cipher_key_length: int
    _cipher_algo: type[CipherAlgorithm]
    _cipher_mode: type[modes.ModeWithInitializationVector]
    _iv_length: int = 16
    _hmac_algorithm: HashAlgorithm

    def __init__(
        self,
        cipher_key_length: int,
        cipher_algorithm: type[CipherAlgorithm],
        cipher_mode: type[modes.ModeWithInitializationVector],
        hmac_algorithm: HashAlgorithm,
    ) -> None:
        """Initialize a new cipher&HMAC encryptor.

        Args:
            cipher_key_length: Key length to use in bytes. Must match what is supported by the
                               specified cipher algorithm
            cipher_algorithm: Type (not object) to use for the cipher algorithm
            cipher_mode: Type (not object) to use for the cipher mode. Must support IV
            hmac_algorithm: Hash algorithm to use for the HMAC operation

        Raises:
            TypeError: If cipher_algorithm or cipher_mode are of non-compatible types
            ValueError: If an invalid cipher_key_length is specified
        """
        if not issubclass(cipher_algorithm, CipherAlgorithm):
            msg = "Algorithm must be subtype of CipherAlgorithm"
            raise TypeError(msg)
        if not issubclass(cipher_mode, modes.Mode):
            msg = "Mode must be subtype of Mode"
            raise TypeError(msg)

        self._cipher_key_length = cipher_key_length
        self._cipher_algo = cipher_algorithm
        self._cipher_mode = cipher_mode
        self._hmac_algorithm = hmac_algorithm

    @override
    def encrypt(self, kd: KeyDerivationOperation, key_material: bytes, data: bytes) -> EncryptionResult:
        key = kd(key_material, self._cipher_key_length + self._hmac_algorithm.digest_size)
        cipher_key = key[: self._cipher_key_length]
        hmac_key = key[self._cipher_key_length :]

        iv = secrets.token_bytes(self._iv_length)

        algo = self._cipher_algo(cipher_key)  # type: ignore[call-arg]
        mode = self._cipher_mode(iv)  # type: ignore[call-arg]
        encryptor = Cipher(algo, mode).encryptor()
        crypto_output = encryptor.update(data) + encryptor.finalize()

        h = HMAC(hmac_key, self._hmac_algorithm)
        h.update(crypto_output)
        tag = h.finalize()

        return EncryptionResult(encrypted_data=crypto_output, tag=tag, nonce=iv)

    @override
    def decrypt(self, kd: KeyDerivationOperation, key_material: bytes, encrypted_data: EncryptionResult) -> bytes:
        key = kd(key_material, self._cipher_key_length + self._hmac_algorithm.digest_size)
        cipher_key = key[: self._cipher_key_length]
        hmac_key = key[self._cipher_key_length :]

        h = HMAC(hmac_key, self._hmac_algorithm)
        h.update(encrypted_data.encrypted_data)
        h.verify(encrypted_data.tag)

        algo = self._cipher_algo(cipher_key)  # type: ignore[call-arg]
        mode = self._cipher_mode(encrypted_data.nonce)  # type: ignore[call-arg]
        decryptor = Cipher(algo, mode).decryptor()

        return decryptor.update(encrypted_data.encrypted_data) + decryptor.finalize()

    @override
    @property
    def nonce_length(self) -> int:
        return self._iv_length

    @override
    @property
    def tag_length(self) -> int:
        return self._hmac_algorithm.digest_size

    @override
    @property
    def identity(self) -> str:
        return (
            f"cipher({self._cipher_algo.name}-{self._cipher_mode.name}"
            f"({self._cipher_key_length*8}),{self._hmac_algorithm.name})"
        )


class XORHMACEncryptor(SymmetricEncrypterAndAuthenticator):
    """Symmetric encryptor and authenticator using XOR and a HMAC combined."""

    _hmac_algorithm: HashAlgorithm

    def __init__(
        self,
        hmac_algorithm: HashAlgorithm,
    ) -> None:
        """Initialize a new XOR & HMAC encryptor.

        Args:
            hmac_algorithm: Hash algorithm to use for the HMAC operation
        """
        self._hmac_algorithm = hmac_algorithm

    @override
    def encrypt(self, kd: KeyDerivationOperation, key_material: bytes, data: bytes) -> EncryptionResult:
        data_len = len(data)

        key = kd(key_material, data_len + self._hmac_algorithm.digest_size)
        hmac_key = key[: self._hmac_algorithm.digest_size]
        cipher_key = key[self._hmac_algorithm.digest_size :]

        crypto_output = bytes(x ^ y for x, y in zip(data, cipher_key, strict=True))

        h = HMAC(hmac_key, self._hmac_algorithm)
        h.update(crypto_output)
        tag = h.finalize()

        return EncryptionResult(encrypted_data=crypto_output, tag=tag)

    @override
    def decrypt(self, kd: KeyDerivationOperation, key_material: bytes, encrypted_data: EncryptionResult) -> bytes:
        data_len = len(encrypted_data.encrypted_data)

        key = kd(key_material, data_len + self._hmac_algorithm.digest_size)
        hmac_key = key[: self._hmac_algorithm.digest_size]
        cipher_key = key[self._hmac_algorithm.digest_size :]

        h = HMAC(hmac_key, self._hmac_algorithm)
        h.update(encrypted_data.encrypted_data)
        h.verify(encrypted_data.tag)

        return bytes(x ^ y for x, y in zip(encrypted_data.encrypted_data, cipher_key, strict=True))

    @override
    @property
    def nonce_length(self) -> int:
        return 0

    @override
    @property
    def tag_length(self) -> int:
        return self._hmac_algorithm.digest_size

    @override
    @property
    def identity(self) -> str:
        return f"xor({self._hmac_algorithm.name})"
