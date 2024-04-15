# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""Python implementation of ECIES (Elliptic Curve Integrated Encryption Scheme).

This library implements ECIES in a configurable matter where the key derivation
function, the encryption and the MAC functions as well as the output format can
be customized.

The library itself provides the following functionality:

Key exchange:
 - ECDH (normal)

Key derivation:
 - HKDF (RFC 5869)
 - ConcatKDF (NIST SP 800-56Ar3)
 - X9.63-KDF

Encryption & MAC:
 - AES-GCM (AEAD)
 - AES-128/256/192 with any HMAC
 - XOR with any HMAC

Output format:
 - Short binary
 - JSON with PEM ephemeral key

"""

from cryptography.hazmat.primitives.asymmetric import ec
from importlib_metadata import PackageNotFoundError as _PackageNotFoundError
from importlib_metadata import version as _version

from .ecies import ECIES

__all__ = ["ECIES"]

__module_name__ = "python_ecies"

try:  # pragma: no cover
    __version__ = _version(__module_name__)
except _PackageNotFoundError as error:  # pragma: no cover
    msg = (
        f"Unable to determine version of package '{__module_name__}'. "
        "If you are on a local development system, use 'pip install -e .[dev]' in order to install the package. "
        "If you are on a productive system, this shouldn't happen. Please report a bug."
    )
    raise ModuleNotFoundError(msg) from error
