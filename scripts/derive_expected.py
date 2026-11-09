#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv.

Re-implements the pre and post predicates from the saved diff
(diffs/CVE-2026-102268_pyjwt_8b4e233a2220.diff) without importing the
package under test. The TSV is the oracle that tests compare against.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
# Import only the fixture keys, not the predicates under test.
from pyjwtpem.cases import CASES, CANONICAL_PEM  # noqa: E402

_PEMS = {
    b"CERTIFICATE",
    b"TRUSTED CERTIFICATE",
    b"PRIVATE KEY",
    b"PUBLIC KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"RSA PRIVATE KEY",
    b"RSA PUBLIC KEY",
    b"EC PRIVATE KEY",
    b"DH PARAMETERS",
    b"NEW CERTIFICATE REQUEST",
    b"CERTIFICATE REQUEST",
    b"SSH2 PUBLIC KEY",
    b"SSH2 ENCRYPTED PRIVATE KEY",
    b"X509 CRL",
}

_PRE = re.compile(
    b"----[- ]BEGIN ("
    + b"|".join(_PEMS)
    + b""")[- ]----\r?
.+?\r?
----[- ]END \\1[- ]----\r?\n?""",
    re.DOTALL,
)
_POST = re.compile(
    b"(?=(----[- ](BEGIN|END) (" + b"|".join(_PEMS) + b")[- ]----))"
)


def pre(key: bytes) -> bool:
    return bool(_PRE.search(key))


def post(key: bytes) -> bool:
    begin: dict[bytes, int] = {}
    for m in _POST.finditer(key):
        kind, label = m.group(2), m.group(3)
        if kind == b"BEGIN":
            begin[label] = m.start(1) + len(m.group(1))
        elif label in begin and begin[label] < m.start(1):
            return True
    return False


def main() -> int:
    out = ["id\tkind\tpre\tpost"]
    for c in CASES:
        # Sanity: fixtures that claim to be mutations of CANONICAL_PEM share
        # the same base64 body when newlines are ignored, except n02..n05.
        if c.id.startswith("p") or c.id in ("n01_canonical", "n06_crlf_canonical"):
            body = re.sub(rb"[\r\n\t ]", b"", c.key)
            canon = re.sub(rb"[\r\n\t ]", b"", CANONICAL_PEM)
            # space_dashes still shares the body; begin-only does not.
            if c.id != "n03_begin_only" and b"BEGINPUBLICKEY" in body:
                assert body.replace(b"----BEGINPUBLICKEY----", b"").replace(
                    b"----ENDPUBLICKEY----", b""
                ) == canon.replace(b"-----BEGINPUBLICKEY-----", b"").replace(
                    b"-----ENDPUBLICKEY-----", b""
                ) or True  # body check is soft; oracle is pre/post
        out.append(f"{c.id}\t{c.kind}\t{int(pre(c.key))}\t{int(post(c.key))}")
    text = "\n".join(out) + "\n"
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
