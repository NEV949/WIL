"""Ed25519 key handling.

Private keys live only on the host, under keys/ (gitignored).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from oracle_hcm.errors import SigningError
from oracle_hcm.paths import keys_dir

__all__ = [
    "PRIVATE_KEY_NAME",
    "PUBLIC_KEY_NAME",
    "KeyPair",
    "generate_keypair",
    "load_keypair",
    "load_private_key",
    "load_public_key",
    "save_keypair",
]

PRIVATE_KEY_NAME = "signer_private.pem"
PUBLIC_KEY_NAME = "signer_public.pem"


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


def generate_keypair() -> KeyPair:
    private_key = Ed25519PrivateKey.generate()
    return KeyPair(private_key=private_key, public_key=private_key.public_key())


def save_keypair(keypair: KeyPair, directory: Path | None = None) -> tuple[Path, Path]:
    """Write the keypair to disk; the private key is owner-readable only."""
    target = directory if directory is not None else keys_dir()
    target.mkdir(parents=True, exist_ok=True)
    private_path = target / PRIVATE_KEY_NAME
    public_path = target / PUBLIC_KEY_NAME
    private_bytes = keypair.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = keypair.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(private_bytes)
    private_path.chmod(0o600)
    public_path.write_bytes(public_bytes)
    return private_path, public_path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SigningError(f"cannot read private key: {path}") from exc
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise SigningError(f"invalid private key file: {path}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError(f"private key is not Ed25519: {path}")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SigningError(f"cannot read public key: {path}") from exc
    try:
        key = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise SigningError(f"invalid public key file: {path}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError(f"public key is not Ed25519: {path}")
    return key


def load_keypair(directory: Path | None = None) -> KeyPair:
    """Load the host keypair from keys/."""
    target = directory if directory is not None else keys_dir()
    private_path = target / PRIVATE_KEY_NAME
    public_path = target / PUBLIC_KEY_NAME
    if not private_path.is_file():
        raise SigningError(
            f"signing key not found at {private_path}; generate one before signing artifacts"
        )
    private_key = load_private_key(private_path)
    public_key = (
        load_public_key(public_path) if public_path.is_file() else private_key.public_key()
    )
    return KeyPair(private_key=private_key, public_key=public_key)
