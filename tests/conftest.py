"""Configuration and fixtures shared between all tests."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec


@pytest.fixture
def random_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())
