# Key storage and rotation

The directory key source loads private JSON Web Key (JWK) files from an existing
directory. See [loading keys][loading-keys] for the initialization calls.

A store with no `.jwk` entries is initialized with a new key set. Like Tang,
initialization assumes one process starts with a given store: starting several
processes on the same empty directory at once is unsupported, and each may
generate its own key set.

Both keys are generated and validated, and the default advertisement is built,
before anything is written. Each key is written to a temporary
`.tangy-<thumbprint>.tmp` file, flushed, and renamed to `<thumbprint>.jwk`; on
Unix the directory is then synchronized. Initialization returns success only
after both keys are persisted. If any step fails, the library attempts to remove
files created by that call and returns the original error; cleanup is best effort.
After a crash, key files are complete or absent: leftover `.tmp` files are ignored.
A crash before the first rename leaves an empty store that regenerates on the
next start. A crash between the two renames leaves a single key, which reports `MissingKeys` until
an operator removes it or restores a complete pair. Complete stores load without
writing, so directory write access is not required.

On Unix, files are created with mode `0440` and set to `0440` through the open
handle before writing, so the final mode does not depend on the caller's umask.
Owner and group read access is intentional, matching Tang. The library never
changes the process umask. On Windows, generated files retain inherited
directory access control lists (ACLs): secure the store directory before
initializing. Windows flushes file contents but has weaker namespace crash
durability than Unix directory synchronization.

Like [Tang](https://github.com/latchset/tang/blob/master/src/keys.c), the store
root and key files are read through symlinks, so Kubernetes Secret volumes and
other linked layouts work. A key entry must resolve to a regular file: dangling
links fail with `KeyRead`, and links to directories or named pipes fail with
`NotAFile`. Operators control where links point and must coordinate manual
edits.

## Manual rotation

For Tang-compatible rotation:

1. Stop the service and any initializers, and back up the store securely.
2. Generate and install a new active signing/recovery pair under new `.jwk`
   filenames, preserving the documented permissions or secured Windows ACLs.
3. Prefix the previous active filenames with `.` to mark them rotated. Keep
   these files while any client still depends on their keys; do not copy them
   into both sets because duplicate identities fail.
4. Validate the directory with `TangyLib::init(KeySource::LocalDir(...))`, then
   restart the service. Old recovery keys remain usable; `/adv/<old-signing-id>`
   returns the active set with an additional old-key signature. Clients that
   retain the old public key can verify that signature.

A rotated-only store fails closed; the library provides no public rotation
helper. This follows [Tang's key handling](https://github.com/latchset/tang/blob/master/src/keys.c)
with that explicit empty-active-set policy.

Stock Clevis enrollment requires `thp` to match a signing key in the advertised
payload, so creating a new binding with a retired thumbprint fails its trust
check even though the old signature is valid. Update enrollment configuration
to the current active signing thumbprint after rotation. Existing bindings
continue to decrypt through the rotated recovery keys. A client retaining the
old public signing key can independently verify the new advertisement's old-key
signature. This limitation also follows from Tang's active-only payloads and
[Clevis's trust check](https://github.com/latchset/clevis/blob/master/src/pins/tang/clevis-encrypt-tang).

Private JWK `Debug` output redacts `d`, and library debug output redacts typed
private keys. Public conversion copies only public fields. Library-owned private
JSON, parsed scalar strings, decoded scalar buffers, scalar encoding buffers and
entropy seeds use zeroizing wrappers. Public field types and generation's
`Vec<String>` return type stay unchanged. Caller-owned strings, copies, crypto
implementation internals and allocator/serialization temporaries remain outside
these guarantees; this is not a claim of complete memory erasure.

[loading-keys]: README.md#loading-keys

