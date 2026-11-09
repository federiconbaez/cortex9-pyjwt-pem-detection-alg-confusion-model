#!/usr/bin/env python3
"""Regenerate results/ and write to the given directory (CI compares with committed)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pyjwtpem.cli import _write_results  # noqa: E402

if __name__ == "__main__":
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results"
    _write_results(dest)
