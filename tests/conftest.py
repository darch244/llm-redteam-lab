import pytest

from rtl.targets.mock_target import MockTarget


@pytest.fixture
def mock_target():
    return MockTarget()
