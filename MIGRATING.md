# Migrate from 0.1 to 1.0.0

Version 1.0.0 changes the API, key validation and key storage.
Install Rust **1.88.0** or later before you update the library.

## Update API calls

| API in 0.1 | Required change in 1.0.0 |
| --- | --- |
| `TangyLib::init`, `adv`, `rec` | Handle `tangy_lib::Result<T>`. Use `?` or match `Error`. |
| `create_new_key_set`, `MyJwkEcKey::thumbprint` | Handle the returned `Result`. |
| `MyJwkEcKey::to_jwk_ec_key(bool)` | Use `to_p521_public_key()` or `to_p521_secret_key()`. |
| `TangyLib::adv_internal` | Use `adv(None)` or `adv(Some(kid))`. |
| `KeySource::Vector(&Vec<&str>)` | Supply a slice (`&[&str]`). Rust also accepts a reference to an existing vector. |
| Active and rotated input keys | Use `KeySource::KeySets { active, rotated }`. |

The conversion methods return P-521 0.14 key types. Use the same dependency
version series if your code uses these types directly.

Public key conversion ignores `d`. Private key conversion requires a valid
private scalar that matches the public point. `to_public_key()` still returns
public JWK fields without validation or changes to metadata.
The `MyJwkEcKey` name and its public fields remain available.

See the [README examples](README.md#usage) for key loading and protocol calls.

## Handle errors

Include a fallback arm when you match the non-exhaustive `Error` enum.
Match error variants and these enums: `Algorithm`, `KeyOperation`,
`RandomPurpose` and `WriteStep`. Do not match error message text.

- `InvalidRequest` identifies invalid client input.
- `InvalidStoredKey` identifies an invalid server key. Match its `Box<Error>`
  source to find the cause. Its location gives a path or an input index.
  Input indices start at zero and identify the active or rotated set.
- I/O errors retain the path and cause.
- Signing and random number errors contain boxed source errors.

Use `source()` to read the error chain. Each message gives its own context
without repeating the cause. `JsonError` gives the category, line and column.
It excludes raw Serde messages that can contain private input.
Validation reasons and serialization contexts are diagnostic text and can change.

## Check keys and requests

Stored keys must have:

- `kty: "EC"` and `crv: "P-521"`.
- Valid public coordinates and a matching private scalar.
- Unpadded Base64URL fields that each decode to exactly 66 bytes.
- `alg: "ES512"` with `sign` and `verify` for signing keys.
- `alg: "ECMR"` with `deriveKey` for recovery keys.

Initialization rejects missing or unsupported key roles and duplicate keys.
This includes identical keys in the active and rotated sets.

Stored keys can have extra operations. Advertisements include only `verify`
for signing keys and `deriveKey` for recovery keys. Advertised recovery keys
omit `use` to prevent incorrect signature requirements in JOSE and Clevis.

Recovery requests must contain a valid P-521 public point.
Requests can omit `alg` and `key_ops`. If supplied, these fields must permit
ECMR and `deriveKey`. Invalid JSON, points or operations return errors.
Responses contain only public key material. JWS fields use unpadded Base64URL.

## Prepare key storage

Supply an existing directory to `LocalDir`. The library reads entries with
names that end in `.jwk`. A name that starts with `.` identifies a rotated key.
The library ignores other files. Directory, read and JSON errors return errors
to the caller.

The library generates keys only if the directory has no active or rotated key
entries. Invalid, incomplete or rotated-only stores return errors without
replacing keys. Slice inputs do not generate or save keys.

Initialization must save both generated keys before it can succeed.
The library writes each key to a temporary file, then renames that file.
The two renames are separate operations. A crash between them leaves an
incomplete store that you must repair. Do not start multiple instances at
the same time on an empty store.

Directory and key paths can use symbolic links. Each key entry must refer to
a regular file. Read the [storage guarantees](KEY_STORAGE.md) before deployment.

Unix key files have mode `0440`, which permits owner and group read access.
On Windows, key files inherit directory access control lists (ACLs).
Set the directory permissions before initialization.
Windows gives less protection against lost file names after a crash than
Unix directory synchronization. CI tests cover Linux and Windows.
Other Unix platforms are not tested.

## Rotate keys

The library advertises only active keys. By default, only active keys sign
advertisements. Use `adv(Some(old_signer_id))` to add a rotated key signature
to the active signatures. Recovery accepts active and rotated ECMR keys.

For new enrollment, stock Clevis requires a signing key thumbprint from the
current advertisement. A rotated key thumbprint fails this check, even if its
signature is valid. Follow the manual rotation procedure in the README.
Keep old recovery keys while clients still need them.

## Protect private values

Debug output and error messages hide private key values.
The library clears its temporary secret values with zeroizing wrappers.
You must manage strings and copies that your code owns.
The API does not guarantee removal of all secret values from memory.
