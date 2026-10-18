mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use p521::elliptic_curve::sec1::ToSec1Point;
use serde_json::{json, Value};
use tangy_lib::{create_new_key_set, KeySource, MyJwkEcKey, TangyLib};

/// Assures: KEY-VALID-001
#[test]
fn typed_conversion_rejects_invalid_field_encodings_and_lengths() {
    for field in ["x", "y", "d"] {
        for encoded in [
            String::new(),
            "%%%".into(),
            "+".repeat(88),
            "/".repeat(88),
            format!("{}=", "A".repeat(88)),
            Base64UrlUnpadded::encode_string(&[1; 65]),
            Base64UrlUnpadded::encode_string(&[1; 67]),
        ] {
            let mut value: Value = serde_json::from_str(SIGNING).unwrap();
            value[field] = json!(encoded);
            let key = fixture_key(&value.to_string());
            assert!(matches!(
                key.to_p521_secret_key(),
                Err(tangy_lib::Error::InvalidKey { .. })
            ));
            if field == "d" {
                assert_eq!(
                    key.to_p521_public_key().unwrap(),
                    fixture_key(SIGNING).to_p521_public_key().unwrap()
                );
            } else {
                assert!(matches!(
                    key.to_p521_public_key(),
                    Err(tangy_lib::Error::InvalidKey { .. })
                ));
            }
        }
    }
}

/// Assures: KEY-VALID-001
#[test]
fn typed_conversion_checks_scalar_boundaries_and_public_points() {
    // SEC 2's P-521 group order, encoded as exactly 66 big-endian bytes.
    let order_hex = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
    let order: Vec<u8> = (0..order_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&order_hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(order.len(), 66);
    for bytes in [vec![0; 66], order.clone(), vec![0xff; 66]] {
        let mut key = fixture_key(SIGNING);
        key.d = Some(Base64UrlUnpadded::encode_string(&bytes));
        assert!(matches!(
            key.to_p521_secret_key(),
            Err(tangy_lib::Error::InvalidKey { .. })
        ));
    }
    let mut one = vec![0; 66];
    one[65] = 1;
    let mut largest = order;
    largest[65] -= 1;
    for bytes in [one, largest] {
        let secret = p521::SecretKey::from_slice(&bytes).unwrap();
        let point = secret.public_key().to_sec1_point(false);
        let mut key = fixture_key(SIGNING);
        key.x = Base64UrlUnpadded::encode_string(point.x().unwrap());
        key.y = Base64UrlUnpadded::encode_string(point.y().unwrap());
        key.d = Some(Base64UrlUnpadded::encode_string(&bytes));
        assert_eq!(
            key.to_p521_secret_key().unwrap().to_bytes(),
            secret.to_bytes()
        );
    }
    for bytes in [[0; 66], [0xff; 66]] {
        let mut key = fixture_key(SIGNING);
        key.x = Base64UrlUnpadded::encode_string(&bytes);
        key.y = Base64UrlUnpadded::encode_string(&bytes);
        assert!(matches!(
            key.to_p521_public_key(),
            Err(tangy_lib::Error::InvalidKey { .. })
        ));
    }
}

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
        let secret = round_trip.to_p521_secret_key().unwrap();
        let public = key.to_public_key();
        assert_eq!(public.to_p521_public_key().unwrap(), secret.public_key());
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

/// Assures: KEY-LOAD-001, KEY-VALID-001
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
                TangyLib::init(KeySource::Vector(&[good, &bad])).is_err(),
                "accepted invalid {field}"
            );
        }
        let mut key: Value = serde_json::from_str(source).unwrap();
        key.as_object_mut().unwrap().remove("d");
        let bad = key.to_string();
        assert!(TangyLib::init(KeySource::Vector(&[SIGNING, RECOVERY, &bad])).is_err());
    }
}

/// Assures: KEY-PRIV-001
#[test]
fn direct_jwk_debug_redacts_the_scalar_and_public_conversion_preserves_metadata() {
    for json in [SIGNING, RECOVERY] {
        let key = fixture_key(json);
        for output in [format!("{key:?}"), format!("{key:#?}")] {
            assert!(!output.contains(key.d.as_ref().unwrap()));
            assert!(output.contains("[REDACTED]"));
            assert!(output.contains(&key.x));
        }
        let public = key.to_public_key();
        assert!(public.d.is_none());
        assert_eq!(key.d, fixture_key(json).d);
        let mut expected = serde_json::to_value(&key).unwrap();
        expected.as_object_mut().unwrap().remove("d");
        assert_eq!(serde_json::to_value(public).unwrap(), expected);
    }
}

/// Assures: KEY-PRIV-001
#[test]
fn library_debug_redacts_active_and_rotated_private_keys() {
    let generated = create_new_key_set().unwrap();
    let active: Vec<_> = generated.iter().map(String::as_str).collect();
    let lib = TangyLib::init(KeySource::KeySets {
        active: &active,
        rotated: &[SIGNING, RECOVERY],
    })
    .unwrap();
    for output in [format!("{lib:?}"), format!("{lib:#?}")] {
        assert!(output.contains("[REDACTED]"));
        for json in active.iter().copied().chain([SIGNING, RECOVERY]) {
            assert!(!output.contains(fixture_key(json).d.as_ref().unwrap()));
        }
    }
}

/// Assures: KEY-VALID-001
#[test]
fn optional_metadata_and_extra_operations_do_not_add_restrictions() {
    let mut signing: Value = serde_json::from_str(SIGNING).unwrap();
    signing["use"] = json!("arbitrary optional use");
    signing["kid"] = json!("not the thumbprint");
    signing["key_ops"] = json!(["sign", "verify", "extra"]);
    signing["x5c"] = json!("opaque certificate metadata");
    let signing = signing.to_string();
    let active = library(&[&signing, RECOVERY]);
    let rotated = TangyLib::init(KeySource::KeySets {
        active: &[SECOND_SIGNING, RECOVERY],
        rotated: &[&signing],
    })
    .unwrap();
    active.adv(Some(&thumbprint(SIGNING))).unwrap();
    rotated.adv(Some(&thumbprint(SIGNING))).unwrap();
    let adv: Value = serde_json::from_str(&active.adv(None).unwrap()).unwrap();
    let body = payload(&adv);
    let key = body["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["alg"] == "ES512")
        .unwrap();
    assert_eq!(key["use"], "arbitrary optional use");
    assert_eq!(key["kid"], "not the thumbprint");
    assert_eq!(key["key_ops"], json!(["verify", "extra"]));
}
