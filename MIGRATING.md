# Migrating from 0.1 to 0.2

The 0.2 series changes fallible return types, key conversion, validation and
storage behavior. The minimum supported Rust version is **1.88.0** (previously
tested on 1.85.1). Update your toolchain before updating the dependency.

## Calls and errors

| API | 0.2 action |
| --- | --- |
| `TangyLib::init`, `adv`, `rec` | Handle `tangy_lib::Result<T>` using `?` or match `Error`. |
| `create_new_key_set`, `MyJwkEcKey::thumbprint` | Handle their typed results. |
| `MyJwkEcKey::to_jwk_ec_key(bool)` | Replace with `to_p521_public_key()` or `to_p521_secret_key()`. |
| `TangyLib::adv_internal` | Use `adv(None)` or `adv(Some(kid))`; advertisement construction is private. |
| `KeySource::Vector(&Vec<&str>)` | Pass a slice (`&[&str]`); existing borrowed vectors coerce to slices. |
| Active and retired input keys | Use `KeySource::KeySets { active, rotated }` to distinguish them. |

The typed conversion helpers return P-521 0.14 public/secret keys. Callers using
these types directly must use the same dependency series. Public conversion
ignores `d`; private conversion requires a valid scalar matching the public point.
`to_public_key()` remains a public JWK projection and does not validate material
or change metadata. The public `MyJwkEcKey` name and fields remain available.

`Error` is non-exhaustive: include a fallback match arm. Match variants and the
`Algorithm`, `KeyOperation`, `RandomPurpose` and `WriteStep` enums rather than
diagnostic strings. `InvalidRequest` identifies bad client input;
`InvalidStoredKey` identifies a server configuration problem and wraps a
`Box<Error>` that can be matched directly. Its `location` identifies a path or
zero-based active/rotated input index. I/O errors preserve paths and causes.
Signing and randomness causes are opaque boxed errors.

Top-level messages give context without repeating causes. Traverse `source()`
to report the chain once. `JsonError` reports only category, line and column,
omitting raw Serde messages that might quote private input. Validation reasons
and serialization contexts are diagnostic text rather than stable matching APIs.
The [README](README.md#usage) contains compiled examples of loading keys and
serving protocol responses.

## Input validation

Stored keys require `kty: "EC"`, `crv: "P-521"`, valid public coordinates and a
matching private scalar. Each coordinate and scalar must encode exactly 66 bytes
as unpadded Base64URL. Signing keys require `alg: "ES512"` plus `sign` and
`verify`; recovery keys require `alg: "ECMR"` plus `deriveKey`. Unsupported or
missing roles and repeated identities are errors, including identical copies
across active and rotated sets.

Extra operations in stored metadata are accepted, but advertisements expose only
`verify` for signing keys and `deriveKey` for recovery keys, matching the roles served.

Recovery requests require a valid P-521 public point. They may omit `alg` and
`key_ops`; supplied values must allow ECMR and `deriveKey`. Malformed JSON,
invalid points and incompatible operations return errors. Responses contain
public key material only, and JWS fields use unpadded Base64URL.

## Loading, persistence and rotation

`LocalDir` requires an existing directory and loads all names ending in `.jwk`.
Names starting with `.` are rotated keys; unrelated files are ignored. Read,
enumeration and parsing failures propagate. Only a directory with no active or
rotated key entries generates keys. Invalid, incomplete and rotated-only stores
fail without replacing existing keys. Slice inputs never generate or persist.

Initialization succeeds only after a generated signing/recovery pair is
persisted. Publication stages complete temporary files before renaming each;
the pair is not one atomic transaction. A crash between renames leaves an
incomplete store requiring operator repair. Concurrent first starts on an empty
store are unsupported. Read paths follow symlinks, and key entries must resolve
to regular files. See the [storage guarantees](KEY_STORAGE.md)
before deploying.

Unix key files have final mode `0440` with intentional owner/group read access.
Windows inherits directory ACLs; secure the directory before initialization.
Windows provides weaker namespace crash durability than Unix directory sync.
Linux and Windows have CI coverage; other Unix platforms are untested.

Only active keys are advertised and sign by default. `adv(Some(old_signer_id))`
adds a rotated signer's signature alongside active signatures. Recovery accepts
rotated ECMR keys, preserving existing bindings. Stock Clevis requires a current
advertised signing thumbprint for new enrollment; a retired thumbprint fails
that trust check even when its signature verifies. Follow the README's manual
rotation procedure and retain old recovery keys while clients depend on them.

Private values are redacted from debug output, and library-owned secret
temporaries use zeroizing wrappers. Caller-owned strings and copies remain the
caller's responsibility; the API does not promise complete memory erasure.
