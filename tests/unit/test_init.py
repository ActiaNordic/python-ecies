"""Tests for module level functionality."""

import python_ecies


def test_version() -> None:
    assert len(python_ecies.__version__) > 0
