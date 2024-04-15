# SPDX-FileCopyrightText: 2024 Actia Nordic AB
# SPDX-License-Identifier: MIT

"""Output/input format writers and parsers."""

import json
import struct

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from typing_extensions import override

from .common import EncryptionResult, OutputFormat

__all__ = ["BinaryOutput"]


class BinaryOutput(OutputFormat):
    """Binary output packing.

    Packs the output of the ECIES into a binary buffer.
    The format is as follows, in little endian format

    .. code-block:: none

         3      2 2      1 1      0 0      0
         1      4 3      6 5      8 7      0
        +--------+--------+--------+--------+
        | KLen   | NLen   | TLen   | PAD    |    Header
        +--------+--------+--------+--------+
        |                                   |
        | Elliptic curve identifier (12b)   |
        |                                   |
        +--------+--------+--------+--------+
        | Public key bytes (KLen bytes)     |
        |...................................|
        +--------+--------+--------+--------+
        | Nonce/IV bytes (NLen bytes)       |
        |...................................|
        +--------+--------+--------+--------+
        | Encrypted bytes                   |
        |...................................|
        |...................................|
        +--------+--------+--------+--------+
        | Tag bytes (TLen bytes)            |
        |...................................|
        +--------+--------+--------+--------+


    Most commonly nonce and tag is 12 or 16 bytes.
    Fixed overhead is 16 bytes.

    Tag is placed at end, making it suitable for streaming operations.
    """

    _curve_name_len = 12

    @override
    def pack(self, ephemeral_public_key: ec.EllipticCurvePublicKey, result: EncryptionResult) -> bytes:
        public_key_bytes = ephemeral_public_key.public_bytes(
            encoding=Encoding.X962, format=PublicFormat.CompressedPoint
        )
        curve_name = ephemeral_public_key.curve.name.ljust(self._curve_name_len, "\00").encode()

        header = struct.pack("<BBBx", len(public_key_bytes), len(result.nonce), len(result.tag))

        return header + curve_name + public_key_bytes + result.nonce + result.encrypted_data + result.tag

    @override
    def unpack(self, input_data: bytes) -> tuple[ec.EllipticCurvePublicKey, EncryptionResult]:
        # Extract the header
        key_len, nonce_len, tag_len = struct.unpack("<BBBx", input_data[0:4])
        data_len = len(input_data) - (4 + self._curve_name_len + key_len + nonce_len + tag_len)

        # Extract the curve
        curve_name = input_data[4 : (4 + self._curve_name_len)].strip(b"\00").decode()
        ec_curve = ec._CURVE_TYPES[curve_name]  # noqa: SLF001

        # Extract the public key
        key_start_idx = 4 + self._curve_name_len
        eph_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec_curve, input_data[key_start_idx : (key_start_idx + key_len)]
        )

        nonce_start = key_start_idx + key_len
        data_start = nonce_start + nonce_len
        tag_start = data_start + data_len

        result = EncryptionResult(
            encrypted_data=input_data[data_start : (data_start + data_len)],
            tag=input_data[tag_start : (tag_start + tag_len)],
            nonce=input_data[nonce_start : (nonce_start + nonce_len)],
        )

        return (eph_public_key, result)


class JSONOutput(OutputFormat):
    """JSON output packing.

    Packs the output of the ECIES into a JSON object.
    """

    @override
    def pack(self, ephemeral_public_key: ec.EllipticCurvePublicKey, result: EncryptionResult) -> bytes:
        json_dict = {
            "public_key": ephemeral_public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            ),
            "data": result.encrypted_data,
            "nonce": result.nonce,
            "tag": result.tag,
        }

        return json.dumps(json_dict).encode()

    @override
    def unpack(self, input_data: bytes) -> tuple[ec.EllipticCurvePublicKey, EncryptionResult]:
        json_dict = json.loads(input_data)

        eph_public_key = load_pem_public_key(json_dict["public_key"])
        if not isinstance(eph_public_key, ec.EllipticCurvePublicKey):
            msg = "Public key is not an elliptic curve public key"
            raise TypeError(msg)

        result = EncryptionResult(
            encrypted_data=json_dict["data"],
            tag=json_dict["tag"],
            nonce=json_dict["nonce"],
        )

        return (eph_public_key, result)
