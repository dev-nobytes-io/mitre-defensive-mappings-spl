import pytest

from mitremap.model import load_model


@pytest.fixture(scope="session")
def model():
    return load_model()
