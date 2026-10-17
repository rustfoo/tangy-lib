mod common;

use std::{collections::BTreeSet, fs};

use common::*;
use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::{json, Value};
use tangy_lib::{Error, KeyLocation, KeySource, TangyLib};

fn signers(adv: &Value, candidates: &[&str]) -> BTreeSet<String> {
    let signatures = adv
        .get("signatures")
        .map_or_else(|| vec![adv], |s| s.as_array().unwrap().iter().collect());
    let mut result = BTreeSet::new();
    for signature in signatures {
        let protected: Value = serde_json::from_slice(&decode(&signature["protected"])).unwrap();
        assert_eq!(protected, json!({"alg":"ES512", "cty":"jwk-set+json"}));
        let bytes = decode(&signature["signature"]);
        assert_eq!(bytes.len(), 132);
        let signature_bytes = Signature::from_slice(&bytes).unwrap();
        let input = format!(
            "{}.{}",
            signature["protected"].as_str().unwrap(),
            adv["payload"].as_str().unwrap()
        );
        let matching: Vec<_> = candidates
            .iter()
            .filter(|json| {
                let point = fixture_key(json)
                    .to_jwk_ec_key(true)
                    .unwrap()
                    .to_encoded_point::<p521::NistP521>()
                    .unwrap();
                VerifyingKey::from_sec1_bytes(point.as_bytes())
                    .unwrap()
                    .verify(input.as_bytes(), &signature_bytes)
                    .is_ok()
            })
            .map(|json| thumbprint(json))
            .collect();
        assert_eq!(matching.len(), 1);
        assert!(result.insert(matching[0].clone()), "duplicate signature");
    }
    result
}

fn verify_rotation(lib: &TangyLib) {
    for (selected, expected) in [
        (None, vec![SECOND_SIGNING]),
        (Some(thumbprint(SECOND_SIGNING)), vec![SECOND_SIGNING]),
        (Some(thumbprint(SIGNING)), vec![SECOND_SIGNING, SIGNING]),
    ] {
        let adv: Value = serde_json::from_str(&lib.adv(selected.as_deref()).unwrap()).unwrap();
        let body = payload(&adv);
        assert_public(&body);
        let ids: BTreeSet<_> = body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| thumbprint(&k.to_string()))
            .collect();
        assert_eq!(
            ids,
            [thumbprint(SECOND_SIGNING), thumbprint(RECOVERY)]
                .into_iter()
                .collect()
        );
        assert_eq!(
            signers(&adv, &[SIGNING, SECOND_SIGNING]),
            expected.iter().map(|k| thumbprint(k)).collect()
        );
    }
}

/// Assures: KEY-ROTATE-001, ADV-SIG-001
#[test]
fn slices_advertise_active_keys_and_sign_with_old_keys_only_when_selected() {
    let lib = TangyLib::init(KeySource::KeySets {
        active: &[SECOND_SIGNING, RECOVERY],
        rotated: &[SIGNING],
    })
    .unwrap();
    verify_rotation(&lib);
    // Vector remains entirely active; all advertised signers sign by default.
    let lib = TangyLib::init(KeySource::Vector(&[SIGNING, SECOND_SIGNING, RECOVERY])).unwrap();
    let adv: Value = serde_json::from_str(&lib.adv(None).unwrap()).unwrap();
    assert_eq!(payload(&adv)["keys"].as_array().unwrap().len(), 3);
    assert_eq!(signers(&adv, &[SIGNING, SECOND_SIGNING]).len(), 2);
}

/// Assures: KEY-ROTATE-001
#[test]
fn directory_dot_prefix_marks_rotated_keys_including_literal_dot_jwk() {
    for rotated_name in [".old.jwk", ".jwk"] {
        let dir = tempfile::tempdir().unwrap();
        for (name, key) in [
            (".old.jwk", SIGNING),
            ("sign.jwk", SECOND_SIGNING),
            ("rec.jwk", RECOVERY),
        ] {
            fs::write(
                dir.path().join(if name == ".old.jwk" {
                    rotated_name
                } else {
                    name
                }),
                key,
            )
            .unwrap();
        }
        fs::write(dir.path().join("ignore.txt"), "not JSON").unwrap();
        verify_rotation(&TangyLib::init(KeySource::LocalDir(dir.path())).unwrap());
    }
}

/// Assures: KEY-ROTATE-001, REC-CORRECT-001
#[test]
fn rotated_recovery_keys_still_recover_pre_rotation_requests() {
    let generated = tangy_lib::create_new_key_set().unwrap();
    let active: Vec<_> = generated.iter().map(String::as_str).collect();
    let slice = TangyLib::init(KeySource::KeySets {
        active: &active,
        rotated: &[SIGNING, RECOVERY],
    })
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (i, json) in active.iter().enumerate() {
        fs::write(dir.path().join(format!("new-{i}.jwk")), json).unwrap();
    }
    fs::write(dir.path().join(".sign.jwk"), SIGNING).unwrap();
    fs::write(dir.path().join(".rec.jwk"), RECOVERY).unwrap();
    let directory = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    for lib in [slice, directory] {
        for vector in vectors() {
            assert_eq!(
                serde_json::from_str::<Value>(
                    &lib.rec(&thumbprint(RECOVERY), &vector["request"].to_string())
                        .unwrap()
                )
                .unwrap(),
                vector["response"]
            );
        }
        let adv: Value = serde_json::from_str(&lib.adv(None).unwrap()).unwrap();
        assert!(!payload(&adv)["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| thumbprint(&key.to_string()) == thumbprint(RECOVERY)));
        assert!(matches!(
            lib.adv(Some(&thumbprint(RECOVERY))),
            Err(Error::ForbiddenOperation { .. })
        ));
    }
}

/// Assures: KEY-ROTATE-001, KEY-STORE-001
#[test]
fn rotated_keys_never_satisfy_missing_active_roles_or_trigger_generation() {
    for (active, missing) in [
        (vec![], (true, true)),
        (vec![SECOND_SIGNING], (false, true)),
        (vec![RECOVERY], (true, false)),
    ] {
        // Use a fresh rotated pair to avoid any duplicate active identities.
        let old = tangy_lib::create_new_key_set().unwrap();
        let rotated: Vec<_> = old.iter().map(String::as_str).collect();
        let result = TangyLib::init(KeySource::KeySets {
            active: &active,
            rotated: &rotated,
        });
        assert!(
            matches!(result, Err(Error::MissingKeys { signing, recovery }) if (signing, recovery) == missing)
        );
        let dir = tempfile::tempdir().unwrap();
        for (i, json) in active.iter().enumerate() {
            fs::write(dir.path().join(format!("active-{i}.jwk")), json).unwrap();
        }
        for (i, json) in rotated.iter().enumerate() {
            fs::write(dir.path().join(format!(".rotated-{i}.jwk")), json).unwrap();
        }
        let before: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert!(
            matches!(TangyLib::init(KeySource::LocalDir(dir.path())), Err(Error::MissingKeys { signing, recovery }) if (signing, recovery) == missing)
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), before.len());
        for path in before {
            assert!(path.exists());
        }
    }
}

/// Assures: KEY-DUP-001, ERR-DIAG-001
#[test]
fn duplicate_slice_identities_report_both_origins_even_with_conflicting_metadata() {
    let mut conflict: Value = serde_json::from_str(SIGNING).unwrap();
    conflict["alg"] = json!("ECMR");
    conflict["key_ops"] = json!(["deriveKey"]);
    conflict["kid"] = json!("metadata does not change identity");
    let conflict = conflict.to_string();
    for copy in [SIGNING, conflict.as_str()] {
        for rotated in [false, true] {
            let error = if rotated {
                TangyLib::init(KeySource::KeySets {
                    active: &[SIGNING, RECOVERY],
                    rotated: &[copy],
                })
            } else {
                TangyLib::init(KeySource::Vector(&[SIGNING, RECOVERY, copy]))
            }
            .unwrap_err();
            assert!(
                matches!(&error, Error::DuplicateKey { kid, first: KeyLocation::Input(0), second } if kid == &thumbprint(SIGNING) && second == &if rotated { KeyLocation::RotatedInput(0) } else { KeyLocation::Input(2) })
            );
            for json in [SIGNING, RECOVERY] {
                assert!(
                    !format!("{error} {error:?}").contains(fixture_key(json).d.as_ref().unwrap())
                );
            }
        }
    }
    assert!(matches!(
        TangyLib::init(KeySource::KeySets {
            active: &[SECOND_SIGNING, RECOVERY],
            rotated: &[SIGNING, SIGNING]
        }),
        Err(Error::DuplicateKey {
            first: KeyLocation::RotatedInput(0),
            second: KeyLocation::RotatedInput(1),
            ..
        })
    ));
}

/// Assures: KEY-DUP-001, KEY-STORE-001
#[test]
fn duplicate_directory_diagnostics_are_sorted_and_do_not_modify_keys() {
    for names in [["z.jwk", "a.jwk"], ["active.jwk", ".old.jwk"]] {
        let dir = tempfile::tempdir().unwrap();
        for name in names {
            fs::write(dir.path().join(name), SIGNING).unwrap();
        }
        fs::write(dir.path().join("rec.jwk"), RECOVERY).unwrap();
        let mut ordered = names;
        ordered.sort();
        let error = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap_err();
        assert!(
            matches!(error, Error::DuplicateKey { kid, first: KeyLocation::File(first), second: KeyLocation::File(second) } if kid == thumbprint(SIGNING) && first == dir.path().join(ordered[0]) && second == dir.path().join(ordered[1]))
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
        for name in names {
            assert_eq!(fs::read_to_string(dir.path().join(name)).unwrap(), SIGNING);
        }
    }
}

/// Assures: KEY-VALID-001, KEY-PRIV-001
#[test]
fn rotated_keys_receive_identical_validation_and_safe_diagnostic_chains() {
    use std::error::Error as _;
    for source in [SIGNING, RECOVERY] {
        for (field, value) in [
            ("crv", json!("P-256")),
            ("kty", json!("RSA")),
            ("x", json!("AA")),
            ("d", json!("AA")),
            (
                "d",
                serde_json::from_str::<Value>(SECOND_SIGNING).unwrap()["d"].clone(),
            ),
            ("alg", json!("unsupported")),
            ("key_ops", json!([])),
            ("d", json!([fixture_key(source).d.unwrap()])),
        ] {
            let mut bad: Value = serde_json::from_str(source).unwrap();
            bad[field] = value;
            let bad = bad.to_string();
            let generated = tangy_lib::create_new_key_set().unwrap();
            let active: Vec<_> = generated.iter().map(String::as_str).collect();
            let validation = TangyLib::init(KeySource::KeySets {
                active: &active,
                rotated: &[&bad],
            })
            .unwrap_err();
            assert!(matches!(
                &validation,
                Error::InvalidStoredKey {
                    location: KeyLocation::RotatedInput(0),
                    ..
                }
            ));
            let mut chain = format!("{validation} {validation:?}");
            let mut cause = validation.source();
            while let Some(source) = cause {
                chain.push_str(&format!("{source} {source:?}"));
                cause = source.source();
            }
            assert!(!chain.contains(fixture_key(source).d.as_ref().unwrap()));
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join(".bad.jwk"), &bad).unwrap();
            assert!(matches!(
                TangyLib::init(KeySource::LocalDir(dir.path())),
                Err(Error::InvalidStoredKey {
                    location: KeyLocation::File(_),
                    ..
                })
            ));
            assert_eq!(
                fs::read_to_string(dir.path().join(".bad.jwk")).unwrap(),
                bad
            );
        }
    }
}
