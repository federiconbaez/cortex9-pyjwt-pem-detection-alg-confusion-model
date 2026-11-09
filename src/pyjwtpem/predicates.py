"""Literal ports of PyJWT ``is_pem_format`` pre/post CVE-2026-102268.

Source lines (see SOURCES.md):
- pre:  jwt/utils.py at 1f8180a211256dfe5cf32294b6753f554a5a4258
        ``_PEM_RE`` / ``is_pem_format`` (diff lines 9-24 of
        diffs/CVE-2026-102268_pyjwt_8b4e233a2220.diff)
- post: jwt/utils.py at 8b4e233a22206b34ec1186e912e75c0b2396ac07
        ``_PEM_MARKER_RE`` / ``is_pem_format`` (diff lines 16-32)
"""

from __future__ import annotations

import re

# Exact set from jwt/utils.py (both revisions).
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

# Pre-fix: rigid block regex (diff - lines).
_PEM_RE = re.compile(
    b"----[- ]BEGIN ("
    + b"|".join(_PEMS)
    + b""")[- ]----\r?
.+?\r?
----[- ]END \\1[- ]----\r?\n?""",
    re.DOTALL,
)


def is_pem_format_pre(key: bytes) -> bool:
    """jwt/utils.py::is_pem_format before 8b4e233a."""
    return bool(_PEM_RE.search(key))


# Post-fix: marker scan that tolerates loader-accepted formatting variants.
_PEM_MARKER_RE = re.compile(
    b"(?=(----[- ](BEGIN|END) (" + b"|".join(_PEMS) + b")[- ]----))"
)


def is_pem_format_post(key: bytes) -> bool:
    """jwt/utils.py::is_pem_format after 8b4e233a."""
    begin_markers: dict[bytes, int] = {}
    for marker in _PEM_MARKER_RE.finditer(key):
        marker_type, label = marker.group(2), marker.group(3)
        if marker_type == b"BEGIN":
            begin_markers[label] = marker.start(1) + len(marker.group(1))
        elif label in begin_markers and begin_markers[label] < marker.start(1):
            return True
    return False
