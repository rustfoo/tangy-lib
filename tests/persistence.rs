mod common;

use std::{collections::BTreeMap, fs, path::Path};

use common::*;
use serde_json::Value;
use tangy_lib::{KeySource, TangyLib};

fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(path).unwrap(),
            )
        })
        .collect()
}

#[test]
fn generated_keys_are_persisted_and_stable_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let first = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    let before = snapshot(dir.path());
    assert_eq!(before.len(), 2);
    let mut ids = Vec::new();
    let mut recovery_id = None;
    for (file, bytes) in &before {
        let key = fixture_key(std::str::from_utf8(bytes).unwrap());
        let id = key.thumbprint();
        assert_eq!(file, &format!("{id}.jwk"));
        key.to_jwk_ec_key(false)
            .to_secret_key::<p521::NistP521>()
            .unwrap();
        if key.alg.as_deref() == Some("ECMR") {
            recovery_id = Some(id.clone());
        }
        ids.push(id);
    }
    ids.sort();
    let request = vectors()[1]["request"].to_string();
    let response = first
        .rec(recovery_id.as_deref().unwrap(), &request)
        .unwrap();
    drop(first);
    let reopened = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    assert_eq!(before, snapshot(dir.path()));
    let adv: Value = serde_json::from_str(&reopened.adv(None).unwrap()).unwrap();
    let mut advertised: Vec<_> = payload(&adv)["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| thumbprint(&k.to_string()))
        .collect();
    advertised.sort();
    assert_eq!(ids, advertised);
    assert_eq!(
        response,
        reopened
            .rec(recovery_id.as_deref().unwrap(), &request)
            .unwrap()
    );
}

#[test]
fn invalid_existing_stores_fail_without_changing_files() {
    for files in [
        vec![("bad.jwk", "{")],
        vec![("sign.jwk", SIGNING)],
        vec![("rec.jwk", RECOVERY)],
        vec![
            ("sign.jwk", SIGNING),
            ("rec.jwk", RECOVERY),
            ("bad.jwk", "{"),
        ],
        vec![(
            "bad.jwk",
            r#"{"kty":"EC","crv":"P-521","x":"AA","y":"AA","alg":"unsupported"}"#,
        )],
    ] {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            fs::write(dir.path().join(name), content).unwrap();
        }
        let before = snapshot(dir.path());
        assert!(TangyLib::init(KeySource::LocalDir(dir.path())).is_err());
        assert_eq!(before, snapshot(dir.path()));
    }
}

#[test]
fn unreadable_key_entry_and_invalid_utf8_are_not_skipped() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("sign.jwk"), SIGNING).unwrap();
    fs::write(dir.path().join("rec.jwk"), RECOVERY).unwrap();
    // A directory cannot be read as a key file even when running as root.
    fs::create_dir(dir.path().join("unreadable.jwk")).unwrap();
    assert!(TangyLib::init(KeySource::LocalDir(dir.path())).is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("invalid.jwk"), [0xff, 0xfe]).unwrap();
    let before = snapshot(dir.path());
    assert!(TangyLib::init(KeySource::LocalDir(dir.path())).is_err());
    assert_eq!(before, snapshot(dir.path()));
}

#[test]
fn nonexistent_directory_and_regular_file_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    assert!(TangyLib::init(KeySource::LocalDir(&dir.path().join("missing"))).is_err());
    let path = dir.path().join("file");
    fs::write(&path, "").unwrap();
    assert!(TangyLib::init(KeySource::LocalDir(&path)).is_err());
}
