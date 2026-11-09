# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only on 2026-11-09.

| Source | Used for | SHA-256 of copy |
|---|---|---|
| NVD `CVE-2026-102268` JSON | ID existence, Analyzed status | see `sources/cve2026/SHA256SUMS` entry `nvd/CVE-2026-102268.json` |
| GHSA-ffc3-869f-jxw9 JSON | advisory, versions ≤2.13.0 → 2.14.0, CWE-347 | `ghsa_rec/CVE-2026-102268.json` |
| commit `8b4e233a22206b34ec1186e912e75c0b2396ac07` diff | the fix | `5a02ddb28db768cf2dde110bc66c97d6dde052c7b48bda5b66f9e85b843830e4` |
| `jwt/utils.py` at parent `1f8180a211256dfe5cf32294b6753f554a5a4258` | pre predicate | `8713a3bc3061781621cfe4483e2133ed0f3c7525124cccc474a13f5b0d95749c` |
| `jwt/utils.py` at `8b4e233a` | post predicate | `e4e3d4faf0b15c47a049940088e256434b6566920ec7163c172ce47684c29ac0` |
| `jwt/algorithms.py` at parent | HMACAlgorithm.prepare_key PEM gate | `b03ff3a9d078e744d5a25a458ebd120a0b6f1af82f16161eed57570c61fcf445` |

No source contained instructions addressed to a tool or agent.
