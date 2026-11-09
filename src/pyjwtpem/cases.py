"""Hand-written fixtures for the PEM-detection model.

Positive cases are mutations of a well-formed RSA public key that the
``cryptography`` loader still accepts (as exercised by the upstream test
``test_hmac_should_reject_loader_accepted_pem_mutations`` in the same commit).
Negative cases must be classified the same way before and after the fix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .predicates import is_pem_format_post, is_pem_format_pre

# Minimal, self-contained RSA public key (2048-bit, generated offline for this
# model; not a production key). Same shape as PyJWT's testkey2_rsa.pub.pem.
CANONICAL_PEM = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzRzXtwNScOgQvvLZOlrV\n"
    b"oIudReXfKIa1KhrkdekaREKP9GhSivGtH0yjbB4q/SA1ZRLR/X0mVLTfAXbQNyxA\n"
    b"LBe/3QNxfrOp0Kpn5yTz6XclMbyrA4HBPGXdHH6zYPUu+1RtxkvwiprV3792apaj\n"
    b"9EU2MhJ9k2ZbJMfQscuES6uFP8nlEyV2YSF3eIQ0cl6uE6Gjhqt8BG20amNUoy8i\n"
    b"8Ls5ez8wVQJE5SCLBJiNBShlkGStuADlfXFLmHwmd3GXioSG/18a5YcxRcel8lmj\n"
    b"HxkeQHCayOYk6x1pXRSmkZYYlt56dwDy5OTzlYyzhfZHx/XbQp+7t4zPTdcmrn5u\n"
    b"VQIDAQAB\n"
    b"-----END PUBLIC KEY-----\n"
)


@dataclass(frozen=True)
class Case:
    id: str
    kind: str  # "pos" | "neg"
    description: str
    key: bytes
    # Independent expected values, derived without calling the model predicates.
    # For "pos": pre must be False, post True. For "neg": both equal to expected_both.
    expected_pre: bool
    expected_post: bool


def _mutate(kind: str) -> bytes:
    if kind == "tab_before_end":
        # Upstream mutation: key.replace(b"-----END", b"\t-----END")
        return CANONICAL_PEM.replace(b"-----END", b"\t-----END")
    if kind == "cr_only":
        # Upstream mutation: key.replace(b"\n", b"\r")
        return CANONICAL_PEM.replace(b"\n", b"\r")
    if kind == "no_newlines":
        # Upstream mutation: key.replace(b"\n", b"")
        return CANONICAL_PEM.replace(b"\n", b"")
    if kind == "space_after_label":
        # Space between label and closing dashes: "BEGIN PUBLIC KEY -----"
        # (loader-tolerant; breaks the rigid pre regex).
        return CANONICAL_PEM.replace(
            b"BEGIN PUBLIC KEY-----", b"BEGIN PUBLIC KEY -----"
        ).replace(b"END PUBLIC KEY-----", b"END PUBLIC KEY -----")
    raise ValueError(kind)


CASES: list[Case] = [
    Case(
        "p01_tab_before_end",
        "pos",
        "tab inserted before END marker (upstream mutation)",
        _mutate("tab_before_end"),
        False,
        True,
    ),
    Case(
        "p02_cr_only",
        "pos",
        "LF replaced by CR (upstream mutation)",
        _mutate("cr_only"),
        False,
        True,
    ),
    Case(
        "p03_no_newlines",
        "pos",
        "all newlines removed (upstream mutation)",
        _mutate("no_newlines"),
        False,
        True,
    ),
    Case(
        "p04_space_dashes",
        "pos",
        "space between PEM label and closing dashes",
        _mutate("space_after_label"),
        False,
        True,
    ),
    Case(
        "n01_canonical",
        "neg",
        "well-formed PEM with LF",
        CANONICAL_PEM,
        True,
        True,
    ),
    Case(
        "n02_hmac_secret",
        "neg",
        "random HMAC secret, no PEM markers",
        b"this-is-a-symmetric-hmac-secret-32b!",
        False,
        False,
    ),
    Case(
        "n03_begin_only",
        "neg",
        "BEGIN without END (upstream incomplete-marker case)",
        b"-----BEGIN PUBLIC KEY-----" * 8,
        False,
        False,
    ),
    Case(
        "n04_empty",
        "neg",
        "empty key",
        b"",
        False,
        False,
    ),
    Case(
        "n05_ssh_rsa_line",
        "neg",
        "SSH public key line (not PEM); detected by is_ssh_key, not is_pem_format",
        b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 user@host\n",
        False,
        False,
    ),
    Case(
        "n06_crlf_canonical",
        "neg",
        "canonical PEM with CRLF (still matches the pre regex)",
        CANONICAL_PEM.replace(b"\n", b"\r\n"),
        True,
        True,
    ),
]


def evaluate_case(case: Case) -> dict:
    pre = is_pem_format_pre(case.key)
    post = is_pem_format_post(case.key)
    return {
        "id": case.id,
        "kind": case.kind,
        "description": case.description,
        "pre": pre,
        "post": post,
        "expected_pre": case.expected_pre,
        "expected_post": case.expected_post,
        "ok": pre == case.expected_pre and post == case.expected_post,
        # Differential: a positive fixture must flip False→True.
        "flips": (not pre) and post,
    }


def hmac_gate(is_pem: Callable[[bytes], bool], key: bytes) -> str:
    """Model of HMACAlgorithm.prepare_key's PEM gate only.

    Returns 'REJECTED_ASYMMETRIC' if the key looks like PEM, else 'ACCEPTED_AS_HMAC'.
    Does not call cryptography and does not sign anything.
    """
    if is_pem(key):
        return "REJECTED_ASYMMETRIC"
    return "ACCEPTED_AS_HMAC"
