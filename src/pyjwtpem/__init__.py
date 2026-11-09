"""Offline model of PyJWT ``is_pem_format`` before and after CVE-2026-102268.

The predicates are literal ports of jwt/utils.py at parent 1f8180a2 (pre) and
fix 8b4e233a (post). HMAC prepare_key behaviour is modelled only as far as
the PEM gate: if ``is_pem_format`` returns True the key is rejected as an
asymmetric key; otherwise the bytes are accepted as an HMAC secret. No JWT is
signed or verified against a third party.
"""

from .predicates import is_pem_format_post, is_pem_format_pre
from .cases import CASES, evaluate_case

__all__ = [
    "is_pem_format_pre",
    "is_pem_format_post",
    "CASES",
    "evaluate_case",
]
