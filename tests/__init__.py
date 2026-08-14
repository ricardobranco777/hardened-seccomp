"""Test package init: makes scripts/*.py importable as plain modules from the tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
