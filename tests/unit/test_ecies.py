"""Tests of python_ecies.ecies module."""

import python_ecies
import python_ecies.factory


def test_default_identity() -> None:
    ecies = python_ecies.factory.get_default_hkdf_aesgcm_binary()

    assert ecies.identity == "ecies-hkdf(sha256)-aesgcm(256,128)"
