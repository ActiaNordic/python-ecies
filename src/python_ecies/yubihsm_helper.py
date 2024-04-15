# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""Helper module for interfacing the library with YubiHSM."""

import yubihsm  # type: ignore[import-not-found]
import yubihsm.objects  # type: ignore[import-not-found]
from cryptography.hazmat.primitives.asymmetric import ec
from typing_extensions import override


class YubiPrivateKey(ec.EllipticCurvePrivateKey):
    """Wrapper to expose a YubiHSM private key object as a EllipticCurvePrivateKey.

    It does not provide the entire EllipticCurvePrivateKey interface, however it is enough to
    do ECIES decrypt (and encrypt) operations.
    """

    _yubi_priv_key: yubihsm.objects.AsymmetricKey

    def __init__(self, yubi_priv_key: yubihsm.objects.AsymmetricKey) -> None:
        """Initialize a new wrapper private key.

        Args:
            yubi_priv_key: The YubiHSM AsymmetricKey to wrap. It is assumed it represents an ellipic
                           curve key.
        """
        self._yubi_priv_key = yubi_priv_key

    @override
    def exchange(self, _algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        return self._yubi_priv_key.derive_ecdh(peer_public_key)

    @override
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._yubi_priv_key.get_public_key()

    @override
    @property
    def curve(self) -> ec.EllipticCurve:
        return self._yubi_priv_key.get_public_key().curve

    @override
    @property
    def key_size(self) -> int:
        return self._yubi_priv_key.get_public_key().key_size

    @override
    def sign(
        self,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        if not isinstance(signature_algorithm, ec.ECDSA):
            msg = "Not allowed!"
            raise NotImplementedError(msg)

        return self._yubi_priv_key.sign_ecdsa(data, signature_algorithm.algorithm)

    @override
    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        msg = "Not allowed!"
        raise NotImplementedError(msg)

    @override
    def private_bytes(
        self,
        _encoding: ec._serialization.Encoding,
        _format: ec._serialization.PrivateFormat,
        _encryption_algorithm: ec._serialization.KeySerializationEncryption,
    ) -> bytes:
        msg = "Not allowed!"
        raise NotImplementedError(msg)
