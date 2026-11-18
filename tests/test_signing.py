"""Key handling and signed manifests."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from oracle_hcm.errors import SigningError
from oracle_hcm.signing.keys import (
    PRIVATE_KEY_NAME,
    PUBLIC_KEY_NAME,
    generate_keypair,
    load_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)
from oracle_hcm.signing.manifest import (
    ApprovalPin,
    Manifest,
    ModelPin,
    build_manifest,
    compute_root_hash,
    manifest_bytes,
    sign_manifest,
    signature_payload,
    verify_manifest,
    verify_signed_manifest,
)
from oracle_hcm.signing.signer import Signer, Verifier

FILES = {
    "pkg/module.py": b"def handler() -> None:\n    return None\n",
    "tests/test_module.py": b"def test_handler() -> None:\n    assert True\n",
}

MODELS = [ModelPin(role="coder", model_id="fake/coder", version="1")]
APPROVALS = [
    ApprovalPin(
        gate_id="approval_spec",
        stage=1,
        approval_id="apr-1",
        status="approved",
        sha256="a" * 64,
    ),
    ApprovalPin(
        gate_id="approval_tests",
        stage=2,
        approval_id="apr-2",
        status="approved",
        sha256="b" * 64,
    ),
]


def _manifest() -> Manifest:
    return build_manifest(
        FILES,
        artifact_id="run-1-REQ-1",
        requirement_id="REQ-1",
        test_report_hash="t-hash",
        security_report_hash="s-hash",
        acceptance_result_hash="a-hash",
        risk_tier="low",
        models=MODELS,
        approvals=APPROVALS,
        log_head_hash="l-hash",
        created_at="2026-01-01T00:00:00+00:00",
    )


def test_keypair_round_trip(tmp_path: Path) -> None:
    keypair = generate_keypair()
    private_path, public_path = save_keypair(keypair, tmp_path)

    assert private_path.name == PRIVATE_KEY_NAME
    assert public_path.name == PUBLIC_KEY_NAME
    loaded = load_keypair(tmp_path)
    original = keypair.public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    restored = loaded.public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert restored == original


def test_the_private_key_stays_out_of_the_manifest(tmp_path: Path) -> None:
    private_path, public_path = save_keypair(generate_keypair(), tmp_path)

    assert private_path.name == PRIVATE_KEY_NAME
    assert public_path.name == PUBLIC_KEY_NAME
    assert private_path.read_bytes() != public_path.read_bytes()


def test_missing_key_raises(tmp_path: Path) -> None:
    with pytest.raises(SigningError):
        load_keypair(tmp_path)


def test_invalid_key_file_raises(tmp_path: Path) -> None:
    broken = tmp_path / "broken.pem"
    broken.write_text("not a key", encoding="utf-8")
    with pytest.raises(SigningError):
        load_private_key(broken)
    with pytest.raises(SigningError):
        load_public_key(broken)


def test_manifest_pins_every_file() -> None:
    manifest = _manifest()
    assert [entry.path for entry in manifest.files] == sorted(FILES)
    assert [entry.size for entry in manifest.files] == [len(FILES[path]) for path in sorted(FILES)]
    assert verify_manifest(manifest) is True


def test_manifest_pins_the_reports_and_the_models() -> None:
    manifest = _manifest()

    assert manifest.test_report_hash == "t-hash"
    assert manifest.security_report_hash == "s-hash"
    assert manifest.acceptance_result_hash == "a-hash"
    assert manifest.risk_tier == "low"
    assert manifest.log_head_hash == "l-hash"
    assert manifest.models == MODELS
    assert [pin.stage for pin in manifest.approvals] == [1, 2]
    assert manifest.approvals[0].approval_id == "apr-1"
    assert manifest.approvals[1].approval_id == "apr-2"


def test_manifest_detects_a_changed_file() -> None:
    manifest = _manifest()
    manifest.files[0].sha256 = "0" * 64
    assert verify_manifest(manifest) is False


def test_the_root_hash_covers_every_field() -> None:
    manifest = _manifest()

    changed = manifest.model_copy(update={"risk_tier": "high"})
    assert compute_root_hash(changed) != manifest.root_hash

    approvals = manifest.model_copy(update={"approvals": []})
    assert compute_root_hash(approvals) != manifest.root_hash

    models = manifest.model_copy(update={"models": []})
    assert compute_root_hash(models) != manifest.root_hash


def test_signed_manifest_verifies(signer: Signer, verifier: Verifier) -> None:
    manifest = _manifest()
    signed = sign_manifest(manifest, signer)
    assert verify_signed_manifest(signed, verifier) is True


def test_signed_manifest_rejects_tampering(signer: Signer, verifier: Verifier) -> None:
    manifest = _manifest()
    signed = sign_manifest(manifest, signer)
    signed.manifest.log_head_hash = "other"
    assert verify_signed_manifest(signed, verifier) is False


def test_the_signature_covers_the_root_hash_only(signer: Signer, verifier: Verifier) -> None:
    manifest = _manifest()
    signed = sign_manifest(manifest, signer)

    assert verifier.verify(signature_payload(manifest.root_hash), signed.signature) is True
    assert verifier.verify(signature_payload("other"), signed.signature) is False


def test_manifest_bytes_are_canonical() -> None:
    manifest = _manifest()
    raw = manifest_bytes(manifest)
    assert b'"created_at"' in raw
    assert raw == manifest_bytes(manifest)
