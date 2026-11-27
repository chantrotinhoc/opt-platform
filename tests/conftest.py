import os

import pytest


def pytest_collection_modifyitems(config, items):
    if os.environ.get("OPT_DATABASE_URL"):
        return
    skip = pytest.mark.skip(reason="needs PostgreSQL: set OPT_DATABASE_URL (see README)")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)
