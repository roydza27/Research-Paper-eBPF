"""Test adapter exposing controlled evaluation corpus tests under research/experiments/tests/."""
import sys
import unittest
from pathlib import Path

# Add research/experiments/split_bypass/scripts and tests to sys.path
SPLIT_BYPASS_DIR = Path(__file__).resolve().parents[1] / "split_bypass"
sys.path.insert(0, str(SPLIT_BYPASS_DIR / "scripts"))
sys.path.insert(0, str(SPLIT_BYPASS_DIR / "tests"))

from test_controlled_evaluation import CorpusDefinitionTests, SummaryTests

__all__ = ["CorpusDefinitionTests", "SummaryTests"]

if __name__ == "__main__":
    unittest.main()
