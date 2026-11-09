# Guía práctica (8 niveles)

Ejercicios **offline y locales** sobre detección de PEM y confusión de
algoritmo. No se firma nada contra terceros. Cada respuesta está
comprobada en `tests/test_model.py`.

Comandos: `PYTHONPATH=src python -m unittest discover -s tests -v`;
`PYTHONPATH=src python -m pyjwtpem case <id>`.

**Básico**

1. **Canónico.** `n01_canonical`: ¿qué dice pre y post? (ambos `True`)
2. **Secreto HMAC.** `n02_hmac_secret`: ¿se parece a PEM? (ambos `False`)

**Intermedio**

3. **Mutación tab.** `p01_tab_before_end`: ¿por qué falla el regex pre?
4. **CR en vez de LF.** `p02_cr_only`: ¿qué exige `\r?\n` del bloque?
5. **Sin saltos.** `p03_no_newlines`: ¿el marcador post aún encuentra BEGIN/END?

**Avanzado**

6. **Puerta HMAC.** Con `hmac_gate`, ¿qué etiqueta da pre y post en un pos?
7. **BEGIN sin END.** `n03_begin_only`: ¿por qué post también es `False`?
8. **Bloque posterior.** `test_later_pem_block_still_detected_post`: un
   prefijo BEGIN-only delante de un PEM completo; ¿lo detecta post?

Más allá: añade una mutación a `cases.py`, regenera
`fixtures/expected.tsv` con `scripts/derive_expected.py` y comprueba que
el modelo coincide con el oráculo independiente.
