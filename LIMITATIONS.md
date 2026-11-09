# Limitations

- **Predicate only.** The model ports `is_pem_format` and the PEM gate of
  `HMACAlgorithm.prepare_key`. It does not import PyJWT, does not call
  `cryptography`, and does not produce a signed JWT.
- **Mutations.** Positive fixtures follow the three upstream mutations in
  the fix commit plus one extra hand-written variant. Which exact variants
  a given `cryptography` release accepts is **not verified** here; the
  model only shows the detection gap.
- **Not modelled:** `is_ssh_key`, JWK JSON rejection, empty-key rejection,
  and the rest of `prepare_key`.
- This is not a finding. Nothing is attributed beyond the commits listed in
  SOURCES.md and the public CVE.
