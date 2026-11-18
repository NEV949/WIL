"""Signing and verification primitives."""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = ["Signer", "Verifier"]


class Signer:
    """Signs bytes with the host Ed25519 private key."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._private_key.sign(data)).decode("ascii")


class Verifier:
    """Verifies Ed25519 signatures produced by a Signer."""

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    def verify(self, data: bytes, signature_b64: str) -> bool:
        try:
            raw = base64.b64decode(signature_b64, validate=True)
        except (ValueError, TypeError):
            return False
        try:
            self._public_key.verify(raw, data)
        except InvalidSignature:
            return False
        return True
