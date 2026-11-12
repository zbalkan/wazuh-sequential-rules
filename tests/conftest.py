import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "slow: waits on the manager's wall clock; deselect with -m 'not slow'",
    )
