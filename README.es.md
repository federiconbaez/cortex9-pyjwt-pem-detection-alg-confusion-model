# cortex9-pyjwt-pem-detection-alg-confusion-model

Modelo diferencial offline de **CVE-2026-102268** (GHSA-ffc3-869f-jxw9):
`is_pem_format` de PyJWT no reconocía variantes de PEM que el loader de
`cryptography` sí acepta, y una clave pública mutada podía usarse como
secreto HMAC (confusión de algoritmo). Educativo, offline y determinista.
No se firma ningún JWT contra terceros.

English: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Dos predicados, siempre en paralelo

| | pre (`1f8180a2`) | post (`8b4e233a`) |
|---|---|---|
| Detección | regex rígida `_PEM_RE` | escaneo de marcadores BEGIN/END |
| Diff | líneas 9–24 del parche guardado | líneas 16–32 |

Las fixtures positivas (mutaciones hechas a mano de una clave RSA local)
deben ser `False` en pre y `True` en post. Las negativas no deben cambiar.

## Cómo ejecutarlo

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

Ver [LIMITATIONS.md](LIMITATIONS.md) y [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.
