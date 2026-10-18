mod common;

use std::collections::BTreeSet;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::*;
use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p521::elliptic_curve::sec1::ToSec1Point;
use serde_json::{json, Value};
use tangy_lib::MyJwkEcKey;

// Verify the exact wire signing input, without reserializing either JWS field.
fn verified_signers(adv: &Value) -> Vec<Option<String>> {
    let payload = payload(adv);
    let keys: Vec<MyJwkEcKey> = serde_json::from_value(payload["keys"].clone()).unwrap();
    let signatures = match adv.get("signatures") {
        Some(signatures) => {
            assert!(adv.get("protected").is_none());
            assert!(adv.get("signature").is_none());
            signatures.as_array().unwrap().iter().collect::<Vec<_>>()
        }
        None => vec![adv],
    };
    signatures
        .into_iter()
        .map(|sig| {
            let protected: Value = serde_json::from_slice(&decode(&sig["protected"])).unwrap();
            assert_eq!(protected, json!({"alg":"ES512", "cty":"jwk-set+json"}));
            let bytes = decode(&sig["signature"]);
            assert_eq!(bytes.len(), 132, "ES512 uses fixed-width R || S");
            let signature = Signature::from_slice(&bytes).unwrap();
            let input = format!(
                "{}.{}",
                sig["protected"].as_str().unwrap(),
                adv["payload"].as_str().unwrap()
            );
            let matches: Vec<_> = keys
                .iter()
                .filter(|key| key.alg.as_deref() == Some("ES512"))
                .filter(|key| {
                    let point = key.to_p521_public_key().unwrap().to_sec1_point(false);
                    VerifyingKey::from_sec1_bytes(point.as_bytes())
                        .unwrap()
                        .verify(input.as_bytes(), &signature)
                        .is_ok()
                })
                .map(|key| key.thumbprint().unwrap())
                .collect();
            assert!(matches.len() <= 1);
            matches.into_iter().next()
        })
        .collect()
}

/// Assures: ADV-SIG-001, KEY-PRIV-001
#[test]
fn advertisements_verify_and_publish_only_public_keys() {
    for signing_keys in [vec![SIGNING], vec![SIGNING, SECOND_SIGNING]] {
        let mut keys = signing_keys.clone();
        keys.push(RECOVERY);
        let lib = library(&keys);
        let mut selections = vec![None];
        selections.extend(signing_keys.iter().map(|key| Some(thumbprint(key))));
        for selection in selections {
            let wire = lib.adv(selection.as_deref()).unwrap();
            let adv: Value = serde_json::from_str(&wire).unwrap();
            assert_public(&adv);
            let payload = payload(&adv);
            assert_public(&payload);
            let advertised = payload["keys"].as_array().unwrap();
            assert_eq!(advertised.len(), keys.len());
            let advertised_ids: BTreeSet<_> = advertised
                .iter()
                .map(|k| {
                    let ops = k["key_ops"].as_array().unwrap();
                    assert!(!ops.contains(&json!("sign")));
                    assert!(ops.contains(&json!(if k["alg"] == "ES512" {
                        "verify"
                    } else {
                        "deriveKey"
                    })));
                    thumbprint(&k.to_string())
                })
                .collect();
            assert_eq!(advertised_ids, keys.iter().map(|k| thumbprint(k)).collect());
            // Clevis requires every advertised verification key to have signed,
            // including when the request names a particular trusted key.
            let expected: BTreeSet<_> = signing_keys.iter().map(|k| thumbprint(k)).collect();
            let signers = verified_signers(&adv);
            assert_eq!(signers.len(), expected.len());
            assert_eq!(
                signers
                    .into_iter()
                    .map(Option::unwrap)
                    .collect::<BTreeSet<_>>(),
                expected
            );
            assert_eq!(adv.get("signatures").is_some(), signing_keys.len() > 1);
        }
        assert_eq!(
            lib.adv(None).unwrap(),
            lib.adv(None).unwrap(),
            "default advertisement is cached"
        );
    }
}

/// Assures: ADV-SIG-001
#[test]
fn advertisement_payload_is_unpadded_for_all_length_remainders() {
    for metadata in ["a", "ab", "abc"] {
        let mut key: Value = serde_json::from_str(SIGNING).unwrap();
        key["kid"] = json!(metadata);
        let key = key.to_string();
        let lib = library(&[&key, RECOVERY]);
        let adv: Value = serde_json::from_str(&lib.adv(None).unwrap()).unwrap();
        assert_eq!(verified_signers(&adv), [Some(thumbprint(SIGNING))]);
    }
}

/// Assures: ADV-SIG-001
#[test]
fn altered_payload_and_signature_do_not_verify() {
    let lib = library(&[SIGNING, RECOVERY]);
    let adv: Value = serde_json::from_str(&lib.adv(None).unwrap()).unwrap();
    let mut changed = adv.clone();
    let mut body = payload(&adv);
    body["tampered"] = json!(true);
    changed["payload"] = json!(Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&body).unwrap()
    ));
    assert_eq!(verified_signers(&changed), [None]);
    let mut changed = adv.clone();
    let mut bytes = decode(&adv["signature"]);
    bytes[65] ^= 1;
    changed["signature"] = json!(Base64UrlUnpadded::encode_string(&bytes));
    assert_eq!(verified_signers(&changed), [None]);
}

/// Assures: REC-CORRECT-001, KEY-PRIV-001
#[test]
fn recovery_matches_independent_vectors() {
    let lib = library(&[SIGNING, RECOVERY]);
    for vector in vectors() {
        let wire = lib
            .rec(&thumbprint(RECOVERY), &vector["request"].to_string())
            .unwrap();
        let response: Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(response, vector["response"]);
        assert_public(&response);
        fixture_key(&wire).to_p521_public_key().unwrap();
    }
}

/// Assures: REC-CORRECT-001
#[test]
fn blinded_client_recovers_its_original_shared_point() {
    let lib = library(&[SIGNING, RECOVERY]);
    let server = fixture_key(RECOVERY).to_p521_public_key().unwrap();
    // Use fixed valid scalars without depending on the server's private key.
    let client = p521::SecretKey::from_slice(&[7; 32]).unwrap();
    let blinder = p521::SecretKey::from_slice(&[11; 32]).unwrap();
    let blinded = p521::ProjectivePoint::from(*client.public_key().as_affine())
        + p521::ProjectivePoint::from(*blinder.public_key().as_affine());
    let point = p521::PublicKey::from_affine(blinded.to_affine())
        .unwrap()
        .to_sec1_point(false);
    let request = json!({
        "kty": "EC", "crv": "P-521",
        "x": Base64UrlUnpadded::encode_string(point.x().unwrap()),
        "y": Base64UrlUnpadded::encode_string(point.y().unwrap()),
    })
    .to_string();
    let response = lib.rec(&thumbprint(RECOVERY), &request).unwrap();
    let response = fixture_key(&response).to_p521_public_key().unwrap();
    let server_point = p521::ProjectivePoint::from(*server.as_affine());
    let unblinded = p521::ProjectivePoint::from(*response.as_affine())
        - server_point * blinder.to_nonzero_scalar().as_ref();
    let expected = server_point * client.to_nonzero_scalar().as_ref();
    assert_eq!(unblinded, expected);
}

/// Assures: REC-CORRECT-001
#[test]
fn recovery_accepts_public_requests_without_optional_metadata() {
    let lib = library(&[SIGNING, RECOVERY]);
    let vector = &vectors()[1];
    let mut request = vector["request"].clone();
    request.as_object_mut().unwrap().remove("alg");
    request.as_object_mut().unwrap().remove("key_ops");
    assert_eq!(
        serde_json::from_str::<Value>(
            &lib.rec(&thumbprint(RECOVERY), &request.to_string())
                .unwrap()
        )
        .unwrap(),
        vector["response"]
    );
}

/// Assures: REQ-REJECT-001
#[test]
fn malformed_recovery_requests_return_errors() {
    let lib = library(&[SIGNING, RECOVERY]);
    let id = thumbprint(RECOVERY);
    for request in ["", "{", "null", "[]", "{}", r#"{"kty":12}"#] {
        assert!(lib.rec(&id, request).is_err(), "accepted {request}");
    }
    let mutations = [
        ("x", json!("%%%")),
        ("x", json!("AA")),
        ("y", json!("")),
        ("x", json!(Base64UrlUnpadded::encode_string(&[0xff; 66]))),
        ("crv", json!("P-256")),
        ("crv", json!("unknown")),
        ("kty", json!("RSA")),
        ("alg", json!("ES512")),
        ("key_ops", json!([])),
        ("key_ops", json!(["sign"])),
    ];
    for (field, value) in mutations {
        let mut request = vectors()[1]["request"].clone();
        request[field] = value;
        assert!(
            lib.rec(&id, &request.to_string()).is_err(),
            "accepted invalid {field}"
        );
    }
    let mut off_curve = vectors()[1]["request"].clone();
    off_curve["x"] = json!(Base64UrlUnpadded::encode_string(&[0; 66]));
    off_curve["y"] = off_curve["x"].clone();
    assert!(lib.rec(&id, &off_curve.to_string()).is_err());
}
