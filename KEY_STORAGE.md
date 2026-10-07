# Key storage and rotation

The directory key source reads private JSON Web Key (JWK) files from an
existing directory. See [loading keys](README.md#loading-keys) for API calls.

## Initialize a store

A store with no `.jwk` entries receives a new key set.
Start only one process on an empty store. If multiple processes start at the
same time, each can generate a different key set.

Before it writes files, the library generates and validates both keys.
It also builds the default advertisement. For each key, the library:

1. Writes a `.tangy-<thumbprint>.tmp` file.
2. Flushes the file contents.
3. Renames the file to `<thumbprint>.jwk`.
4. Synchronizes the directory on Unix.

Initialization succeeds only after both keys are saved.
If a step fails, the library tries to remove files created by that call.
It returns the original error. File removal can also fail.

After a crash, each key file is complete or absent.
The library ignores remaining `.tmp` files.

- A crash before the first rename leaves no key files. The next start generates
  a new key set.
- A crash between renames leaves one key file. Initialization returns
  `MissingKeys` until you remove that file or restore a complete pair.

The library reads complete stores without writing to them.
These stores do not require directory write access.

## Set file permissions

On Unix, the library creates files with mode `0440`.
It also sets mode `0440` through the open file handle before writing.
The final mode is independent of the process umask.
Owner and group read access is intentional. The library does not change
the process umask.

On Windows, generated files inherit directory access control lists (ACLs).
Set the directory permissions before initialization.
Windows flushes file contents. It gives less protection against lost file names
after a crash than Unix directory synchronization.

## Use symbolic links

The library follows symbolic links for the store directory and key files.
This permits Kubernetes Secret volumes and other directories that use links.
Each key entry must refer to a regular file.
A broken link returns `KeyRead`. A link to a directory or named pipe returns
`NotAFile`.

Control the link targets and coordinate manual file changes with the service.

## Rotate keys manually

The library has no public rotation helper.
Use this procedure for Tang-compatible rotation:

1. Stop the service and all processes that can initialize the store.
2. Make a secure backup of the store.
3. Generate and install a new active signing and recovery key pair.
   Use new `.jwk` file names. Keep the required Unix permissions or Windows ACLs.
4. Add `.` to the start of each previous active file name.
   This marks those keys as rotated. Keep them while clients need them.
   Do not keep copies in both sets. Duplicate keys cause initialization to fail.
5. Validate the directory with `TangyLib::init(KeySource::LocalDir(...))`.
6. Restart the service after validation succeeds.

A store with only rotated keys returns an error.
Old recovery keys remain available for existing bindings.
The `/adv/<old-signing-id>` response contains the active key set and an
additional signature from the old key. Clients with the old public signing key
can verify this signature.

For new enrollment, stock Clevis requires `thp` to match a signing key in the
advertisement payload. A rotated key thumbprint fails this check, even if its
signature is valid. After rotation, set the enrollment configuration to the
current active signing key thumbprint.

This behavior follows Tang's active key advertisements and the Clevis trust
check. See [Tang key handling](https://github.com/latchset/tang/blob/master/src/keys.c)
and the [Clevis trust check](https://github.com/latchset/clevis/blob/master/src/pins/tang/clevis-encrypt-tang).

## Protect private values

JWK `Debug` output hides `d`. Library debug output also hides typed private keys.
Public key conversion copies only public fields.

The library uses zeroizing wrappers to clear these temporary secret values:

- Private JSON and parsed scalar strings.
- Decoded scalar buffers and scalar encoding buffers.
- Random number seeds.

Public field types and the `Vec<String>` key generation result remain unchanged.
You must manage strings and copies that your code owns.
The library does not guarantee removal of secret values from cryptographic
internals, allocator memory or serialization temporaries.
It does not guarantee removal of all secret values from memory.
