import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--no-network", action="store_true", default=False, help="Skip network tests"
    )
    parser.addoption(
        "--no-intensive", action="store_true", default=False, help="Skip intensive tests"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "network: mark test as needing network")
    config.addinivalue_line("markers", "intensive: mark test as intensive")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--no-network"):
        skip_network = pytest.mark.skip(reason="Need network access to run and --no-network specified")
        for item in items:
            if "network" in item.keywords:
                item.add_marker(skip_network)
        
    if config.getoption("--no-intensive"):
        skip_intensive = pytest.mark.skip(reason="Intensive tests skipped with --no-intensive")
        for item in items:
            if "intensive" in item.keywords:
                item.add_marker(skip_intensive)