"""CLI: ``python -m pyjwtpem case <id>|all`` and ``python -m pyjwtpem results <dir>``."""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path

from .cases import CASES, evaluate_case, hmac_gate
from .predicates import is_pem_format_post, is_pem_format_pre


def _write_results(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rows = [evaluate_case(c) for c in CASES]
    path = out / "cases.csv"
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "id",
                "kind",
                "pre",
                "post",
                "expected_pre",
                "expected_post",
                "ok",
                "flips",
                "hmac_pre",
                "hmac_post",
                "description",
            ],
        )
        w.writeheader()
        for r, c in zip(rows, CASES):
            w.writerow(
                {
                    **{k: r[k] for k in ("id", "kind", "pre", "post", "expected_pre", "expected_post", "ok", "flips")},
                    "hmac_pre": hmac_gate(is_pem_format_pre, c.key),
                    "hmac_post": hmac_gate(is_pem_format_post, c.key),
                    "description": r["description"],
                }
            )
    summary = out / "summary.csv"
    with summary.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["metric", "value"])
        w.writerow(["cases", len(rows)])
        w.writerow(["ok", sum(1 for r in rows if r["ok"])])
        w.writerow(["pos", sum(1 for r in rows if r["kind"] == "pos")])
        w.writerow(["pos_flips", sum(1 for r in rows if r["kind"] == "pos" and r["flips"])])
        w.writerow(["neg", sum(1 for r in rows if r["kind"] == "neg")])
    # SHA256SUMS of the CSVs only (deterministic across platforms).
    with (out / "SHA256SUMS").open("w") as fh:
        for name in ("cases.csv", "summary.csv"):
            data = (out / name).read_bytes()
            fh.write(f"{hashlib.sha256(data).hexdigest()}  {name}\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pyjwtpem")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("case", help="evaluate one fixture or all")
    c.add_argument("id")
    r = sub.add_parser("results", help="write deterministic CSV artefacts")
    r.add_argument("dir")
    args = p.parse_args(argv)
    if args.cmd == "case":
        if args.id == "all":
            for case in CASES:
                row = evaluate_case(case)
                print(
                    f"{row['id']}\tkind={row['kind']}\tpre={row['pre']}\tpost={row['post']}\t"
                    f"ok={row['ok']}\tflips={row['flips']}"
                )
            return 0
        match = next((c for c in CASES if c.id == args.id), None)
        if match is None:
            print(f"unknown case: {args.id}", file=sys.stderr)
            return 2
        row = evaluate_case(match)
        print(row)
        return 0 if row["ok"] else 1
    if args.cmd == "results":
        _write_results(Path(args.dir))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
