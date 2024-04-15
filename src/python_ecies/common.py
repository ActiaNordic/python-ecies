# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""Common type definitions and base classes."""

import abc
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from cryptography.hazmat.primitives.asymmetric import ec

__all__ = [
    "EncryptionResult",
    "ECDHOperation",
    "KeyDerivationOperation",
    "SymmetricEncrypterAndAuthenticator",
    "OutputFormat",
]


@dataclass
class EncryptionResult:
    """The result of an encryption & authentication operation.

    Attributes:
        encrypted_data: The actual encrypted result bytes.
        tag: Authentication tag for verifying integrity of encrypted data.
        nonce:

    """

    encrypted_data: bytes
    tag: bytes
    nonce: bytes = b""


class ECDHOperation(Protocol):
    """Protocol for ECDH operation.

    ECDH takes a public key and a private key and computes a shared secret
    """

    __call__: Callable[[Any, ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey], bytes]


class KeyDerivationOperation(abc.ABC):
    """Base class for key derivation operation.

    Key derivation takes an input key material and a desired key length, and derive a new key
    of the requested length.
    """

    @abc.abstractmethod
    def __call__(self, key_material: bytes, key_length: int) -> bytes:
        """Perform key derivation.

        Args:
            key_material: Input key material
            key_length: Requested output key length, in bytes
        """

    @property
    @abc.abstractmethod
    def identity(self) -> str:
        """The operation identity."""


class SymmetricEncrypterAndAuthenticator(abc.ABC):
    """Base class for a AEAD (authenticated encryption) operation.

    This can be fullfilled either by an AEAD algorithm such as AES-GCM or ChaCha20Poly1305, or
    by a combination of a symmetric encryption algorithm (AES, XOR) and a MAC such as HMAC-SHA2
    """

    @abc.abstractmethod
    def encrypt(self, kd: KeyDerivationOperation, key_material: bytes, data: bytes) -> EncryptionResult:
        """Encrypt data and compute authentication tag.

        Encrypt and compute the authentication tag using key_material and the specified key
        derivation function.

        Args:
            kd: Key derivation operation to utilize for deriving the required key(s)
            key_material: Input key material for the key derivation function
            data: Data to be encrypted

        Returns:
            A EncryptionResult with the encrypted data, the authentication tag and any
            nonce/IV generated during the encrpytion operation that is required for decryption.
        """

    @abc.abstractmethod
    def decrypt(self, kd: KeyDerivationOperation, key_material: bytes, encrypted_data: EncryptionResult) -> bytes:
        """Authenticate the data and (if valid) decrypt it.

        Args:
            kd: Key derivation operation to utilize for deriving the required key(s)
            key_material: Input key material for the key derivation function
            encrypted_data: Data that has been encrypted, including tag and nonce/IV

        Returns:
            The decrypted data.
        """

    @property
    @abc.abstractmethod
    def tag_length(self) -> int:
        """The tag length generated/consumed by the algorithm."""

    @property
    @abc.abstractmethod
    def nonce_length(self) -> int:
        """The length of the nonce/IV generated and consumed by the algorithm."""

    @property
    @abc.abstractmethod
    def identity(self) -> str:
        """The operation identity."""


class OutputFormat(abc.ABC):
    """Base class for output format packing/unpacking operations.

    Each output format defines how the result from a ECIES encryption should be packed into bytes,
    and reversed, parsed from bytes into input that can be authenticated and decrypted
    """

    @abc.abstractmethod
    def pack(self, ephemeral_public_key: ec.EllipticCurvePublicKey, result: EncryptionResult) -> bytes:
        """Pack encrypted data and the ephemeral public key used to derive the shared secret into bytes.

        Args:
            ephemeral_public_key: The public key generated for shared secret derivation
            result: The output of the encryption operation

        Returns:
            Bytes with the result of the packing operation
        """

    @abc.abstractmethod
    def unpack(self, input_data: bytes) -> tuple[ec.EllipticCurvePublicKey, EncryptionResult]:
        """Unpack ephemeral public key and encrypted data, ie the reverse of "pack".

        It is expected that unpack(pack()) returns back the same data.

        Args:
            input_data: Packed data to unpack

        Returns:
            Tuple of ephemeral public key and the encryption result (data, tag and nonce)
        """
