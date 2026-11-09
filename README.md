# cortex9-pyjwt-pem-detection-alg-confusion-model

Offline differential model of **CVE-2026-102268** (GHSA-ffc3-869f-jxw9):
PyJWT's `is_pem_format` missed PEM formatting variants that the
`cryptography` loader still accepts, so a mutated public key could be used
as an HMAC secret (algorithm confusion). Educational, offline,
deterministic. No JWT is signed against a third party.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## Two predicates, always side by side

| | pre (`1f8180a2`) | post (`8b4e233a`) |
|---|---|---|
| Detection | rigid `_PEM_RE` block regex | `_PEM_MARKER_RE` BEGIN/END marker scan |
| Diff | lines 9–24 of the saved patch | lines 16–32 |

Positive fixtures (hand-written mutations of a local RSA public key) must
be `False` under pre and `True` under post. Negatives must not flip.

## Run

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
PYTHONPATH=src python -m pyjwtpem case all
```

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
