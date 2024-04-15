# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""The main ECIES encryption/decryption operation."""

from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec

from .common import (
    ECDHOperation,
    KeyDerivationOperation,
    OutputFormat,
    SymmetricEncrypterAndAuthenticator,
)

__all__ = ["ECIES"]


def _default_ecdh(public_key: ec.EllipticCurvePublicKey, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.exchange(ec.ECDH(), public_key)


class ECIES:
    """The main ECIES encryption/decryption operation.

    Represents the configuration of a full ECIES operation, and can perform both encryption
    and decryption using the specific config.

    Example usage:

    .. code-block:: python

        from python_ecies import ECIES
        from python_ecies.key_derivation import HKDF
        from python_ecies.symmetric import AESGCMEncrypter
        from python_ecies.format import BinaryOutput

        E = ECIES(HKDF(), AESGCMEncrypter(32), BinaryOutput())

        # Encryption
        public_key = get_public_key_for_encryption()
        encrypted_data = E.encrypt(b"Test data input", public_key)

        # Decryption
        private_key = get_private_key_for_decryption()
        original_data = E.decrypt(encrypted_data, private_key)

    """

    kd_oper: KeyDerivationOperation
    encrypter: SymmetricEncrypterAndAuthenticator
    output_format: OutputFormat
    ecdh_oper: ECDHOperation

    def __init__(
        self,
        key_deriver: KeyDerivationOperation,
        encrypter: SymmetricEncrypterAndAuthenticator,
        output_format: OutputFormat,
        ecdh: Optional[ECDHOperation] = None,
    ) -> None:
        """Initialize a new ECIES object.

        Args:
            key_deriver: The key derivation function to use.
            encrypter: The symmetric encryption and verification module to use. Should perform
                       both encryption and verification of the encrypted data.
            output_format: The output/input format serializer.
            ecdh: Advanced. Change the ECDH operation to use for shared secret generation.
        """
        self.kd_oper = key_deriver
        self.encrypter = encrypter
        self.output_format = output_format
        self.ecdh_oper = ecdh if ecdh else _default_ecdh

    def encrypt(self, data: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """Perform ECIES encryption based on the configuration of the ECIES object."""
        # Generate the ephemeral keypair
        ephemeral_key = ec.generate_private_key(public_key.curve)

        # Generate a shared secret via ECDH
        shared_secret = self.ecdh_oper(public_key, ephemeral_key)

        # Perform key derivation and symmetric encryption
        result = self.encrypter.encrypt(self.kd_oper, shared_secret, data)

        # Pack the output data
        return self.output_format.pack(ephemeral_public_key=ephemeral_key.public_key(), result=result)

    def decrypt(self, data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Perofrm ECIES decryption based on the configuration of the ECIES object."""
        # Extract the ephemeral key and the other parts of the data
        ephemeral_pub_key, encrypted_data = self.output_format.unpack(data)

        # Generate shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub_key)

        # Perform key derivation, symmetric decryption and authentication
        return self.encrypter.decrypt(self.kd_oper, shared_secret, encrypted_data)

    @property
    def identity(self) -> str:
        """Identity unique for the specific configuration of the ECIES object."""
        return f"ecies-{self.kd_oper.identity}-{self.encrypter.identity}"
