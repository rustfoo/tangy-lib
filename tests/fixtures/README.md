# Protocol fixtures

All private keys here are public test data. Never use them outside tests.

`es512.json` and `ecmr.json` preserve the original crate's test keys.
`es512-second.json` is a P-521 signing key derived from the fixed scalar
`0x123456789abcdef0123456789abcdef` using Python cryptography 44.0.0.

`recovery.json` contains requests whose public points are `r*G`, with client
scalars `1` and `0xabcdef0123456789fedcba987654321`. Responses were computed
independently using cryptography's `ec.derive_private_key((d*r) % n,
ec.SECP521R1()).public_key().public_numbers()`, where `d` is the recovery key's
private scalar and `n` is the P-521 group order. Coordinates use 66-byte,
big-endian, unpadded Base64URL encoding. The first vector tests multiplication
by the generator; the second tests a nontrivial input point.

`thumbprints.json` records SHA-256 hashes computed with Python hashlib over
compact JSON containing only `crv`, `kty`, `x`, and `y`, in that order, encoded
with unpadded Base64URL. These include the two original thumbprint constants.

Both the thumbprints and full recovery responses are independently checked
against [Latchset JOSE](https://github.com/latchset/jose) with:

```sh
python3 scripts/check-fixtures.py
```

The script invokes `jose jwk thp` and `jose jwk exc` and compares their output
with the committed expected values. As in
[Tang's recovery handler](https://github.com/latchset/tang/blob/master/src/tangd.c),
it adds `alg: ECMR` and `key_ops: [deriveKey]` to the exchange result. Ordinary
Rust tests use only the committed fixtures, without Python or JOSE dependencies.
