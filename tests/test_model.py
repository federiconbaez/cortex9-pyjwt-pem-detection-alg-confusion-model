"""Differential and adversarial tests for the PyJWT PEM-detection model."""

from __future__ import annotations

import csv
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pyjwtpem.cases import CASES, evaluate_case, hmac_gate  # noqa: E402
from pyjwtpem.predicates import is_pem_format_post, is_pem_format_pre  # noqa: E402


class TestDifferential(unittest.TestCase):
    def test_every_case_matches_hand_written_expectation(self):
        for c in CASES:
            with self.subTest(c.id):
                row = evaluate_case(c)
                self.assertTrue(row["ok"], row)

    def test_every_positive_flips_false_to_true(self):
        flips = [evaluate_case(c) for c in CASES if c.kind == "pos"]
        self.assertGreaterEqual(len(flips), 3)
        for row in flips:
            with self.subTest(row["id"]):
                self.assertTrue(row["flips"], row)

    def test_negatives_do_not_flip(self):
        for c in CASES:
            if c.kind != "neg":
                continue
            with self.subTest(c.id):
                row = evaluate_case(c)
                self.assertEqual(row["pre"], row["post"])

    def test_hmac_gate_rejects_after_fix(self):
        for c in CASES:
            if c.kind != "pos":
                continue
            with self.subTest(c.id):
                self.assertEqual(hmac_gate(is_pem_format_pre, c.key), "ACCEPTED_AS_HMAC")
                self.assertEqual(hmac_gate(is_pem_format_post, c.key), "REJECTED_ASYMMETRIC")


class TestDeriveExpected(unittest.TestCase):
    def test_independent_oracle_matches_fixtures(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "derive_expected.py")],
            check=True,
            capture_output=True,
            text=True,
        )
        lines = [ln for ln in proc.stdout.splitlines() if ln and not ln.startswith("id")]
        by_id = {c.id: c for c in CASES}
        self.assertEqual(len(lines), len(CASES))
        for ln in lines:
            cid, kind, pre_s, post_s = ln.split("\t")
            c = by_id[cid]
            self.assertEqual(kind, c.kind)
            self.assertEqual(int(pre_s), int(c.expected_pre))
            self.assertEqual(int(post_s), int(c.expected_post))
            # Oracle equals the model under test.
            self.assertEqual(bool(int(pre_s)), is_pem_format_pre(c.key))
            self.assertEqual(bool(int(post_s)), is_pem_format_post(c.key))


class TestAdversarial(unittest.TestCase):
    def test_later_pem_block_still_detected_post(self):
        # Upstream test_hmac_should_reject_a_later_pem_block: a BEGIN-only
        # prefix followed by a full PEM must still be detected post-fix.
        from pyjwtpem.cases import CANONICAL_PEM

        key = b"-----BEGIN PUBLIC KEY-----" + CANONICAL_PEM
        self.assertTrue(is_pem_format_post(key))
        # Pre also matches because the second block is well-formed.
        self.assertTrue(is_pem_format_pre(key))

    def test_mismatched_labels_not_pem(self):
        key = (
            b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END CERTIFICATE-----\n"
        )
        self.assertFalse(is_pem_format_pre(key))
        self.assertFalse(is_pem_format_post(key))

    def test_binary_noise(self):
        key = bytes(range(256)) * 4
        self.assertFalse(is_pem_format_pre(key))
        self.assertFalse(is_pem_format_post(key))


class TestResultsArtefact(unittest.TestCase):
    def test_committed_results_match_regeneration(self):
        import tempfile
        from pyjwtpem.cli import _write_results

        with tempfile.TemporaryDirectory() as tmp:
            _write_results(Path(tmp))
            for name in ("cases.csv", "summary.csv", "SHA256SUMS"):
                a = (ROOT / "results" / name).read_bytes()
                b = (Path(tmp) / name).read_bytes()
                self.assertEqual(a, b, name)


if __name__ == "__main__":
    unittest.main()
