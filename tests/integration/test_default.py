"""Smoketests for quick verification of functionality."""

import secrets

from cryptography.hazmat.primitives.asymmetric import ec

import python_ecies
import python_ecies.factory


def test_default_smoketest(random_private_key: ec.EllipticCurvePrivateKey) -> None:
    ecies = python_ecies.factory.get_default_hkdf_aesgcm_binary()

    test_data = secrets.token_bytes(256)

    encrypted = ecies.encrypt(test_data, random_private_key.public_key())
    decrypted = ecies.decrypt(encrypted, random_private_key)

    assert len(encrypted) > len(test_data)
    assert decrypted == test_data


def test_secg_smoketest(random_private_key: ec.EllipticCurvePrivateKey) -> None:
    ecies = python_ecies.factory.get_sec1_concatkdf_aescbc_sha256_binary()

    test_data = secrets.token_bytes(256)

    encrypted = ecies.encrypt(test_data, random_private_key.public_key())
    decrypted = ecies.decrypt(encrypted, random_private_key)

    assert len(encrypted) > len(test_data)
    assert decrypted == test_data
