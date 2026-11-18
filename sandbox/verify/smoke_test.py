"""Smoke test executed inside the sandbox container (baked into the image)."""


def test_toolchain_is_importable() -> None:
    import faker
    import hypothesis
    import mypy
    import pydantic
    import pytest

    assert pydantic.VERSION
    assert faker.VERSION
    assert hypothesis.__version__
    assert pytest.__version__
    assert mypy.__file__


def test_synthetic_data_only() -> None:
    from faker import Faker

    fake = Faker()
    Faker.seed(1234)
    name = fake.name()
    assert isinstance(name, str) and name
