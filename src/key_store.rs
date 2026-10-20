// SPDX-License-Identifier: MIT OR Apache-2.0

//! Load, validate and persist the private keys used by a Tang server.
//!
//! This module turns [`KeySource`] inputs into a key set for [`TangyLib`]. The
//! JWK module handles JSON Web Key representation and cryptographic conversion;
//! this module applies server-key roles, tracks active and rotated keys, rejects
//! duplicate identities, and manages directory storage.
//!
//! [`KeySource::LocalDir`] reads an existing directory in sorted path order for
//! deterministic diagnostics. Filenames ending in `.jwk` are key entries; a
//! leading `.` marks a rotated key. Other entries, including temporary `.tmp`
//! files left by interrupted publication, are ignored. Directory roots and key
//! paths follow symbolic links, and each key entry must resolve to a regular
//! file. Enumeration and read failures propagate with their paths.
//!
//! [`KeySource::Vector`] treats every supplied key as active, while
//! [`KeySource::KeySets`] accepts separate active and rotated slices. Both load
//! directly from strings without generating or writing keys. Every input passes
//! the same validation: a P-521 private key must match its public coordinates;
//! signing keys require `ES512` with `sign` and `verify`; recovery keys require
//! elliptic-curve message recovery (`ECMR`) with `deriveKey`. Repeated public-key
//! thumbprints fail even for identical copies or keys in different sets.
//! [`Error::InvalidStoredKey`] identifies the file or input index and retains
//! its validation cause; [`Error::DuplicateKey`] identifies both origins.
//!
//! Validated entries retain typed private keys, public metadata and their active
//! status. Public metadata omits the private scalar and the `sign` operation;
//! debug output redacts typed private material. Private key strings read from
//! disk and parsed scalar temporaries use zeroizing wrappers. The protocol
//! module uses these entries for advertisements and recovery, and requires both
//! an active signing key and an active recovery key. Rotated keys remain
//! available to protocol operations but do not satisfy those active-role checks.
//!
//! Directory initialization generates a new pair only when there are no active
//! or rotated `.jwk` entries. Corrupt, unreadable, incomplete and rotated-only
//! stores return errors without generating replacements. Loading an existing
//! valid set requires no writes. Rotation is supplied through filenames or
//! explicit input sets; this module does not rotate keys automatically.
//!
//! For an empty directory, generation, validation and construction of the default
//! advertisement finish before writing starts. Both private keys are written to
//! newly created `.tangy-<thumbprint>.tmp` files and synchronized before either is
//! renamed to `<thumbprint>.jwk`. On Unix, the directory is then synchronized.
//! Initialization succeeds only after these steps finish. A reported publication
//! failure triggers best-effort removal of files created by that call and returns
//! the original error, including its [`WriteStep`].
//!
//! Publication makes each key file complete or absent; the pair is not one atomic
//! transaction. A crash before the first rename leaves ignored temporary files
//! and permits generation on restart. A crash between renames can leave an
//! incomplete store that reports [`Error::MissingKeys`] until repaired. Like
//! Tang, initialization assumes one process controls the store: simultaneous
//! first starts and concurrent operator edits are unsupported, and no lock is used.
//!
//! Unix files are created with restrictive permissions and set to mode `0440`
//! through their open handles, allowing owner and group reads independently of
//! the process's file-creation mask. Windows files inherit directory access
//! control lists, so callers must secure the directory before initialization.
//! File contents are synchronized on both platforms; Windows omits directory
//! synchronization and has weaker durability for filename changes after a crash.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use p521::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::{
    create_new_key_set, jwk::parse_private_jwk, Algorithm, Error, JsonError, KeyLocation,
    KeyOperation, MyJwkEcKey, Result, TangyLib, WriteStep,
};

// Only public JSON is retained; private material is parsed once at init.
#[derive(Debug)]
pub(crate) struct StoredKey {
    pub(crate) public: MyJwkEcKey,
    pub(crate) material: KeyMaterial,
    pub(crate) active: bool,
}

// Avoid formatting crypto private keys, including through TangyLib's Debug.
pub(crate) enum KeyMaterial {
    Signing(SigningKey),
    Recovery(p521::SecretKey),
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Signing(_) => "Signing([REDACTED])",
            Self::Recovery(_) => "Recovery([REDACTED])",
        })
    }
}

/// Private key inputs. Every set must have active signing and recovery keys.
#[derive(PartialEq)]
pub enum KeySource<'a> {
    /// Load `.jwk` entries; dot-prefixed filenames identify rotated keys.
    /// A genuinely empty store generates and persists a new pair.
    /// Only one process may initialize an empty store at a time.
    LocalDir(&'a Path),
    /// Load an entirely active slice without generating or writing keys.
    Vector(&'a [&'a str]),
    /// Load explicit active and rotated slices without persistence or generation.
    KeySets {
        active: &'a [&'a str],
        rotated: &'a [&'a str],
    },
}

fn require_operation(
    key: &MyJwkEcKey,
    kid: &str,
    algorithm: Algorithm,
    operation: KeyOperation,
) -> Result<()> {
    if key.alg.as_deref() != Some(algorithm.as_str())
        || !key
            .key_ops
            .as_ref()
            .is_some_and(|ops| ops.iter().any(|op| op == operation.as_str()))
    {
        return Err(Error::ForbiddenOperation {
            kid: kid.into(),
            algorithm,
            operation,
        });
    }
    Ok(())
}

pub(crate) fn parse_stored_key(json: &str) -> Result<Zeroizing<MyJwkEcKey>> {
    parse_private_jwk(json).map_err(|source| Error::key_cause("invalid JSON", JsonError(source)))
}

fn validate_stored_key(jwk: Zeroizing<MyJwkEcKey>, kid: &str) -> Result<StoredKey> {
    match jwk.alg.as_deref() {
        Some("ES512") => {
            require_operation(&jwk, kid, Algorithm::Es512, KeyOperation::Sign)?;
            require_operation(&jwk, kid, Algorithm::Es512, KeyOperation::Verify)?;
        }
        Some("ECMR") => require_operation(&jwk, kid, Algorithm::Ecmr, KeyOperation::DeriveKey)?,
        _ => return Err(Error::invalid_key("algorithm must be ES512 or ECMR")),
    }
    let secret = jwk.to_p521_secret_key()?;
    let material = if jwk.alg.as_deref() == Some("ES512") {
        KeyMaterial::Signing(SigningKey::from(&secret))
    } else {
        KeyMaterial::Recovery(secret)
    };
    let mut public = jwk.to_public_key();
    if let Some(ops) = &mut public.key_ops {
        ops.retain(|op| op != "sign");
    }
    Ok(StoredKey {
        public,
        material,
        active: true,
    })
}

type Keys = BTreeMap<String, StoredKey>;

pub(super) fn initialize(source: KeySource<'_>) -> Result<TangyLib> {
    match source {
        KeySource::LocalDir(dir) => {
            let keys = load_directory(dir)?;
            if keys.is_empty() {
                publish(dir)
            } else {
                TangyLib::from_keys(keys)
            }
        }
        KeySource::Vector(active) => TangyLib::from_keys(load_inputs(active, &[])?),
        KeySource::KeySets { active, rotated } => {
            TangyLib::from_keys(load_inputs(active, rotated)?)
        }
    }
}

// Every identity must be unique across active and rotated keys.
fn load_keys<'a>(entries: impl IntoIterator<Item = (KeyLocation, bool, &'a str)>) -> Result<Keys> {
    let mut keys = Keys::new();
    let mut origins = BTreeMap::new();
    for (location, active, json) in entries {
        let invalid = |source| Error::InvalidStoredKey {
            location: location.clone(),
            source: Box::new(source),
        };
        let jwk = parse_stored_key(json).map_err(invalid)?;
        let kid = jwk.thumbprint().map_err(invalid)?;
        // Identity conflicts fail even when the second copy changes policy metadata.
        if let Some(first) = origins.insert(kid.clone(), location.clone()) {
            return Err(Error::DuplicateKey {
                kid,
                first,
                second: location.clone(),
            });
        }
        let mut key = validate_stored_key(jwk, &kid).map_err(invalid)?;
        key.active = active;
        keys.insert(kid, key);
    }
    Ok(keys)
}

fn load_inputs(active: &[&str], rotated: &[&str]) -> Result<Keys> {
    let active = active.iter().enumerate();
    let rotated = rotated.iter().enumerate();
    load_keys(
        active
            .map(|(index, json)| (KeyLocation::Input(index), true, *json))
            .chain(rotated.map(|(index, json)| (KeyLocation::RotatedInput(index), false, *json))),
    )
}

fn read_key(path: &Path) -> Result<Zeroizing<String>> {
    let read_error = |source| Error::KeyRead {
        path: path.into(),
        source,
    };
    // Like Tang, follow symlinks. Reject non-files before opening so directories
    // and FIFOs fail alike everywhere; a dangling link is a read error.
    if !fs::metadata(path).map_err(read_error)?.is_file() {
        return Err(Error::NotAFile { path: path.into() });
    }
    let mut json = Zeroizing::new(String::new());
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut json))
        .map_err(read_error)?;
    Ok(json)
}

fn load_directory(dir: &Path) -> Result<Keys> {
    let mut paths = fs::read_dir(dir)
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<io::Result<Vec<_>>>()
        })
        .map_err(|source| Error::KeyDirectory {
            path: dir.into(),
            source,
        })?;
    paths.sort();
    let mut files = Vec::new();
    for path in paths {
        let name = path.file_name().unwrap_or_default().as_encoded_bytes();
        // Like Tang, `.jwk` names are keys and a leading `.` marks rotation.
        // Unrelated files, including interrupted `.tmp` writes, are ignored.
        if name.ends_with(b".jwk") {
            let active = !name.starts_with(b".");
            let json = read_key(&path)?;
            files.push((KeyLocation::File(path), active, json));
        }
    }
    load_keys(
        files
            .iter()
            .map(|(location, active, json)| (location.clone(), *active, json.as_str())),
    )
}

fn create_key_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    // Unix: restricted from creation, then set explicitly so the umask cannot
    // change the final mode. Windows keeps the directory's inherited ACLs.
    #[cfg(unix)]
    options.mode(0o440);
    let file = options.open(path)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o440))?;
    Ok(file)
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn write_error(path: &Path, operation: WriteStep) -> impl FnOnce(io::Error) -> Error + '_ {
    move |source| Error::KeyWrite {
        path: path.into(),
        operation,
        source,
    }
}

// Generate a key set and persist it. Both keys are written and flushed to
// temporary files before either is renamed into place, so key files are complete
// or absent after a crash; leftover `.tmp` files are ignored on load. Names are
// fresh thumbprints, so rename replaces nothing in practice.
fn publish(dir: &Path) -> Result<TangyLib> {
    let generated = Zeroizing::new(create_new_key_set()?);
    let inputs: Vec<&str> = generated.iter().map(String::as_str).collect();
    // Validate and build the default advertisement before writing anything.
    let library = TangyLib::from_keys(load_inputs(&inputs, &[])?)?;
    let mut created = Vec::new();
    let result = write_keys(dir, &generated, &mut created);
    if result.is_err() {
        // These keys were never returned or served, so remove everything this
        // call created and report the original failure. Removal is best effort.
        for path in &created {
            let _ = fs::remove_file(path);
        }
    }
    result.map(|()| library)
}

fn write_keys(dir: &Path, generated: &[String], created: &mut Vec<PathBuf>) -> Result<()> {
    let mut renames = Vec::new();
    for json in generated {
        let kid = parse_stored_key(json)?.thumbprint()?;
        let temporary = dir.join(format!(".tangy-{kid}.tmp"));
        let mut file =
            create_key_file(&temporary).map_err(write_error(&temporary, WriteStep::Create))?;
        created.push(temporary.clone());
        fault_point("write")
            .and_then(|()| file.write_all(json.as_bytes()))
            .map_err(write_error(&temporary, WriteStep::Write))?;
        file.sync_all()
            .map_err(write_error(&temporary, WriteStep::Synchronize))?;
        renames.push((temporary, dir.join(format!("{kid}.jwk"))));
    }
    for (temporary, destination) in renames {
        fault_point("rename")
            .and_then(|()| fs::rename(&temporary, &destination))
            .map_err(write_error(&destination, WriteStep::Publish))?;
        created.push(destination);
    }
    fault_point("sync-dir")
        .and_then(|()| sync_directory(dir))
        .map_err(write_error(dir, WriteStep::Synchronize))
}

/// Test-only fault point for child test processes. `TANGY_TEST_FAULT=<point>:<n>`
/// fails the nth hit of a point; `TANGY_TEST_PAUSE=<point>:<n>` writes the file
/// named by `TANGY_TEST_READY` and blocks there so the parent can kill it.
#[cfg(test)]
fn fault_point(point: &'static str) -> io::Result<()> {
    use std::sync::Mutex;
    static HITS: Mutex<BTreeMap<&str, usize>> = Mutex::new(BTreeMap::new());
    let hit = match HITS.lock() {
        Ok(mut hits) => {
            let count = hits.entry(point).or_default();
            *count += 1;
            *count
        }
        Err(_) => return Err(io::Error::other("fault point state poisoned")),
    };
    let selected = |name| {
        std::env::var(name)
            .is_ok_and(|value| value.split_once(':') == Some((point, &hit.to_string())))
    };
    if selected("TANGY_TEST_FAULT") {
        return Err(io::Error::other("injected failure"));
    }
    if selected("TANGY_TEST_PAUSE") {
        if let Some(ready) = std::env::var_os("TANGY_TEST_READY") {
            fs::write(ready, b"ready")?;
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    Ok(())
}

#[cfg(not(test))]
fn fault_point(_: &'static str) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::{
        process::{Child, Command},
        thread,
        time::{Duration, Instant},
    };

    fn names(dir: &Path, suffix: &str) -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(suffix)
            })
            .collect();
        paths.sort();
        paths
    }

    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }

    struct RunningChild(Child);
    impl Drop for RunningChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // Fault points read process-global environment, so they are only set in
    // child processes running `child_process`, never in the parent test.
    fn child(action: &str, dir: &Path, env: &[(&str, &str)]) -> RunningChild {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "key_store::tests::child_process", "--nocapture"])
            .env("TANGY_TEST_ACTION", action)
            .env("TANGY_TEST_DIR", dir);
        for (name, value) in env {
            command.env(name, value);
        }
        RunningChild(command.spawn().unwrap())
    }

    fn wait_for(path: &Path) {
        let start = Instant::now();
        while !path.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "child did not reach {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    // A test harness child, run only by the tests below.
    #[test]
    fn child_process() {
        let Ok(action) = std::env::var("TANGY_TEST_ACTION") else {
            return;
        };
        let dir = PathBuf::from(std::env::var_os("TANGY_TEST_DIR").unwrap());
        match action.as_str() {
            "init" => {
                TangyLib::init(KeySource::LocalDir(&dir)).unwrap();
            }
            "expect-failure" => {
                let expected = std::env::var("TANGY_TEST_EXPECT").unwrap();
                let error = TangyLib::init(KeySource::LocalDir(&dir)).unwrap_err();
                assert!(
                    matches!(error, Error::KeyWrite { operation, ref source, .. } if format!("{operation:?}") == expected && source.to_string() == "injected failure"),
                    "unexpected error: {error:?}"
                );
            }
            #[cfg(unix)]
            "umask" => {
                use std::os::unix::fs::PermissionsExt;
                // Only this subprocess changes its own umask.
                unsafe {
                    libc::umask(0);
                }
                TangyLib::init(KeySource::LocalDir(&dir)).unwrap();
                let keys = names(&dir, ".jwk");
                assert_eq!(keys.len(), 2);
                for path in keys {
                    assert_eq!(
                        fs::metadata(path).unwrap().permissions().mode() & 0o777,
                        0o440
                    );
                }
                assert_eq!(
                    unsafe { libc::umask(0) },
                    0,
                    "library changed process umask"
                );
            }
            _ => panic!("unknown child action"),
        }
    }

    /// Assures: KEY-PUBLISH-001, KEY-STORE-001, ERR-DIAG-001
    #[test]
    fn injected_failures_remove_created_files_and_retry_cleanly() {
        // Failing the second rename removes the first published key; failing
        // the directory sync removes both.
        for (fault, expected) in [
            ("write:1", "Write"),
            ("write:2", "Write"),
            ("rename:1", "Publish"),
            ("rename:2", "Publish"),
            ("sync-dir:1", "Synchronize"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("unrelated"), b"preserve me").unwrap();
            let mut process = child(
                "expect-failure",
                dir.path(),
                &[("TANGY_TEST_FAULT", fault), ("TANGY_TEST_EXPECT", expected)],
            );
            assert!(process.0.wait().unwrap().success(), "{fault}");
            assert_eq!(
                snapshot(dir.path()),
                BTreeMap::from([(dir.path().join("unrelated"), b"preserve me".to_vec())]),
                "{fault}"
            );
            TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
            assert_eq!(names(dir.path(), ".jwk").len(), 2);
            assert!(names(dir.path(), ".tmp").is_empty());
        }
    }

    /// Assures: KEY-PUBLISH-001, KEY-STORE-001
    #[test]
    fn process_death_leaves_complete_files_and_ignored_temporaries() {
        for renamed in 0..=1 {
            let dir = tempfile::tempdir().unwrap();
            let signals = tempfile::tempdir().unwrap();
            let ready = signals.path().join("ready");
            let pause = format!("rename:{}", renamed + 1);
            let mut process = child(
                "init",
                dir.path(),
                &[
                    ("TANGY_TEST_PAUSE", &pause),
                    ("TANGY_TEST_READY", ready.to_str().unwrap()),
                ],
            );
            wait_for(&ready);
            process.0.kill().unwrap();
            process.0.wait().unwrap();
            // Every visible key is complete; unfinished keys remain temporary.
            let published = names(dir.path(), ".jwk");
            let temporaries = names(dir.path(), ".tmp");
            assert_eq!(published.len(), renamed);
            assert_eq!(temporaries.len(), 2 - renamed);
            for path in &published {
                validate_stored_key(
                    parse_stored_key(&fs::read_to_string(path).unwrap()).unwrap(),
                    "published",
                )
                .unwrap();
            }
            let before = snapshot(dir.path());
            let result = TangyLib::init(KeySource::LocalDir(dir.path()));
            if renamed == 0 {
                // Nothing was published, so the store is still empty.
                result.unwrap();
                assert_eq!(names(dir.path(), ".jwk").len(), 2);
                for path in temporaries {
                    assert_eq!(fs::read(&path).unwrap(), before[&path]);
                }
            } else {
                // A lone published key is an incomplete store, as in Tang.
                assert!(matches!(result, Err(Error::MissingKeys { .. })));
                assert_eq!(before, snapshot(dir.path()));
            }
        }
    }

    /// Assures: KEY-PERM-001
    #[cfg(unix)]
    #[test]
    fn permissive_umask_subprocess_produces_final_mode_0440() {
        let dir = tempfile::tempdir().unwrap();
        let mut process = child("umask", dir.path(), &[]);
        assert!(process.0.wait().unwrap().success());
    }

    /// Assures: KEY-STORE-001
    #[cfg(unix)]
    #[test]
    fn complete_store_loads_without_directory_write_access() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("sign.jwk"),
            include_str!("../tests/fixtures/es512.json"),
        )
        .unwrap();
        fs::write(
            dir.path().join("rec.jwk"),
            include_str!("../tests/fixtures/ecmr.json"),
        )
        .unwrap();
        let before = snapshot(dir.path());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o550)).unwrap();
        let result = TangyLib::init(KeySource::LocalDir(dir.path()));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
        assert_eq!(before, snapshot(dir.path()));
    }
}
