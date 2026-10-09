mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use serde_json::{json, Value};
use tangy_lib::{create_new_key_set, KeySource, MyJwkEcKey, TangyLib};

/// Assures: KEY-ID-001
#[test]
fn thumbprints_match_independently_computed_values_and_ignore_metadata() {
    let expected: Value = serde_json::from_str(include_str!("fixtures/thumbprints.json")).unwrap();
    for (name, source) in [
        ("es512.json", SIGNING),
        ("ecmr.json", RECOVERY),
        ("es512-second.json", SECOND_SIGNING),
    ] {
        let mut key = fixture_key(source);
        assert_eq!(key.thumbprint().unwrap(), expected[name]);
        assert_eq!(key.to_public_key().thumbprint().unwrap(), expected[name]);
        key.alg = None;
        key.key_ops = None;
        key.kid = Some("arbitrary metadata".into());
        key.use_ = Some("sig".into());
        assert_eq!(key.thumbprint().unwrap(), expected[name]);
    }
}

/// Assures: KEY-GEN-001
#[test]
fn generated_keys_and_serialization_round_trips_are_usable() {
    let generated = create_new_key_set().unwrap();
    assert_eq!(generated.len(), 2);
    let lib = library(&generated.iter().map(String::as_str).collect::<Vec<_>>());
    let mut algorithms = Vec::new();
    for source in generated {
        let key = fixture_key(&source);
        algorithms.push(key.alg.clone().unwrap());
        assert_eq!(key.kty, "EC");
        assert_eq!(key.crv, "P-521");
        for field in [&key.x, &key.y, key.d.as_ref().unwrap()] {
            assert!(!field.contains('='));
            assert_eq!(Base64UrlUnpadded::decode_vec(field).unwrap().len(), 66);
        }
        let encoded = serde_json::to_string(&key).unwrap();
        let round_trip: MyJwkEcKey = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&key).unwrap(),
            serde_json::to_value(&round_trip).unwrap()
        );
        let secret = round_trip
            .to_jwk_ec_key(false)
            .unwrap()
            .to_secret_key::<p521::NistP521>()
            .unwrap();
        let public = key.to_public_key();
        assert_eq!(
            public
                .to_jwk_ec_key(true)
                .unwrap()
                .to_public_key::<p521::NistP521>()
                .unwrap(),
            secret.public_key()
        );
        let public_json = serde_json::to_value(&public).unwrap();
        assert_public(&public_json);
        assert_eq!(
            fixture_key(&public_json.to_string()).thumbprint().unwrap(),
            key.thumbprint().unwrap()
        );
        match key.alg.as_deref().unwrap() {
            "ES512" => {
                assert_eq!(key.key_ops, Some(vec!["sign".into(), "verify".into()]));
                lib.adv(Some(&key.thumbprint().unwrap())).unwrap();
            }
            "ECMR" => {
                assert_eq!(key.key_ops, Some(vec!["deriveKey".into()]));
                lib.rec(
                    &key.thumbprint().unwrap(),
                    &vectors()[0]["request"].to_string(),
                )
                .unwrap();
            }
            _ => panic!("unexpected algorithm"),
        }
    }
    algorithms.sort();
    assert_eq!(algorithms, ["ECMR", "ES512"]);
}

/// Assures: KEY-LOAD-001
#[test]
fn malformed_or_incomplete_vectors_return_errors() {
    for keys in [
        vec![],
        vec!["{"],
        vec![SIGNING],
        vec![RECOVERY],
        vec![SIGNING, RECOVERY, "{"],
        vec![SIGNING, RECOVERY, "{}"],
    ] {
        assert!(TangyLib::init(KeySource::Vector(&keys)).is_err());
    }
}

/// Assures: KEY-LOAD-001
#[test]
fn invalid_stored_keys_return_errors() {
    for source in [SIGNING, RECOVERY] {
        let mutations = [
            ("x", json!("%%%")),
            ("y", json!("AA")),
            ("crv", json!("P-384")),
            ("kty", json!("RSA")),
            ("d", Value::Null),
            ("d", json!("%%%")),
            ("d", json!(Base64UrlUnpadded::encode_string(&[0; 66]))),
            (
                "d",
                serde_json::from_str::<Value>(SECOND_SIGNING).unwrap()["d"].clone(),
            ),
            ("alg", Value::Null),
            ("alg", json!("unsupported")),
            ("key_ops", Value::Null),
            ("key_ops", json!([])),
            ("key_ops", json!(["sign"])),
            ("key_ops", json!(["verify"])),
        ];
        for (field, value) in mutations {
            let mut key: Value = serde_json::from_str(source).unwrap();
            key[field] = value;
            let bad = key.to_string();
            let good = if source == SIGNING { RECOVERY } else { SIGNING };
            assert!(
                TangyLib::init(KeySource::Vector(&vec![good, &bad])).is_err(),
                "accepted invalid {field}"
            );
        }
        let mut key: Value = serde_json::from_str(source).unwrap();
        key.as_object_mut().unwrap().remove("d");
        let bad = key.to_string();
        assert!(TangyLib::init(KeySource::Vector(&vec![SIGNING, RECOVERY, &bad])).is_err());
    }
}
