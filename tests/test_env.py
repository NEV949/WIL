"""Start-up loading of the .env file."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from oracle_hcm.config.env import env_file_path, load_env


def test_load_env_reads_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("ORACLE_TEST_TOKEN=abc123\n", encoding="utf-8")
    monkeypatch.delenv("ORACLE_TEST_TOKEN", raising=False)

    assert load_env(env_file) is True
    assert os.environ["ORACLE_TEST_TOKEN"] == "abc123"


def test_load_env_does_not_override_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("ORACLE_TEST_TOKEN=from_file\n", encoding="utf-8")
    monkeypatch.setenv("ORACLE_TEST_TOKEN", "from_environment")

    assert load_env(env_file) is True
    assert os.environ["ORACLE_TEST_TOKEN"] == "from_environment"


def test_load_env_can_override_on_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("ORACLE_TEST_TOKEN=from_file\n", encoding="utf-8")
    monkeypatch.setenv("ORACLE_TEST_TOKEN", "from_environment")

    assert load_env(env_file, override=True) is True
    assert os.environ["ORACLE_TEST_TOKEN"] == "from_file"


def test_load_env_without_a_file_is_not_an_error(tmp_path: Path) -> None:
    assert load_env(tmp_path / "missing.env") is False


def test_env_file_path_points_at_the_project_dotenv() -> None:
    assert env_file_path().name == ".env"


def test_the_package_loads_the_env_file_on_import() -> None:
    import oracle_hcm

    assert oracle_hcm.load_env is load_env
    assert oracle_hcm.__version__
