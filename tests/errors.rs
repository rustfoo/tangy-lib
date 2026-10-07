mod common;

use std::error::Error as StdError;

use common::*;
use serde_json::{json, Value};
use tangy_lib::{Error, JsonError, KeyLocation, KeySource, TangyLib};

fn diagnostics(error: &dyn StdError) -> String {
    let mut messages = format!("{error} {error:?}");
    let mut source = error.source();
    while let Some(error) = source {
        messages.push_str(&format!(" {error} {error:?}"));
        source = error.source();
    }
    messages
}

#[test]
fn incomplete_key_sets_identify_the_missing_roles() {
    for (keys, expected) in [
        (vec![], (true, true)),
        (vec![SIGNING], (false, true)),
        (vec![RECOVERY], (true, false)),
    ] {
        let error = TangyLib::init(KeySource::Vector(&keys)).unwrap_err();
        match error {
            Error::MissingKeys { signing, recovery } => assert_eq!((signing, recovery), expected),
            _ => panic!("unexpected error: {error:?}"),
        }
    }
}

#[test]
fn invalid_stored_keys_include_their_origin_and_safe_source_chain() {
    let error = TangyLib::init(KeySource::Vector(&vec![SIGNING, RECOVERY, "{"])).unwrap_err();
    assert!(matches!(
        &error,
        Error::InvalidStoredKey {
            location: KeyLocation::Input(2),
            ..
        }
    ));
    let invalid = error.source().unwrap().downcast_ref::<Error>().unwrap();
    assert!(matches!(invalid, Error::InvalidKey { .. }));
    let json = invalid
        .source()
        .unwrap()
        .downcast_ref::<JsonError>()
        .unwrap();
    assert_eq!(json.category(), serde_json::error::Category::Eof);
    assert_eq!(json.line(), 1);
    assert!(json.column() > 0);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.jwk");
    std::fs::write(&path, "{").unwrap();
    let error = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap_err();
    assert!(
        matches!(&error, Error::InvalidStoredKey { location: KeyLocation::File(actual), .. } if actual == &path)
    );
    assert!(error.source().is_some());
}

#[test]
fn stored_policy_and_crypto_errors_retain_validation_causes() {
    let mut key: Value = serde_json::from_str(SIGNING).unwrap();
    key["key_ops"] = json!(["verify"]);
    let invalid = key.to_string();
    let error = TangyLib::init(KeySource::Vector(&vec![RECOVERY, &invalid])).unwrap_err();
    assert!(matches!(
        &error,
        Error::InvalidStoredKey {
            location: KeyLocation::Input(1),
            ..
        }
    ));
    assert!(matches!(
        error.source().unwrap().downcast_ref::<Error>().unwrap(),
        Error::ForbiddenOperation { kid, algorithm: "ES512", operation: "sign" } if kid == &thumbprint(SIGNING)
    ));

    key["key_ops"] = json!(["sign", "verify"]);
    key["x"] = json!("%%%");
    let invalid = key.to_string();
    let error = TangyLib::init(KeySource::Vector(&vec![RECOVERY, &invalid])).unwrap_err();
    let validation = error.source().unwrap().downcast_ref::<Error>().unwrap();
    assert!(matches!(validation, Error::InvalidKey { .. }));
    assert!(validation.source().unwrap().is::<elliptic_curve::Error>());
}

#[test]
fn persistence_errors_include_paths_and_original_io_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing");
    let error = TangyLib::init(KeySource::LocalDir(&path)).unwrap_err();
    assert!(matches!(&error, Error::KeyDirectory { path: actual, .. } if actual == &path));
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );

    let path = dir.path().join("invalid.jwk");
    std::fs::write(&path, [0xff]).unwrap();
    let error = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap_err();
    assert!(matches!(&error, Error::KeyRead { path: actual, .. } if actual == &path));
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn protocol_errors_distinguish_missing_keys_forbidden_operations_and_requests() {
    let library = library(&[SIGNING, RECOVERY]);
    let id = thumbprint(RECOVERY);
    let signing_id = thumbprint(SIGNING);
    let request = vectors()[1]["request"].to_string();
    for error in [
        library.adv(Some("unknown")).unwrap_err(),
        library.rec("unknown", &request).unwrap_err(),
    ] {
        assert!(matches!(error, Error::KeyNotFound { kid } if kid == "unknown"));
    }
    assert!(
        matches!(library.adv(Some(&id)), Err(Error::ForbiddenOperation { kid, algorithm: "ES512", operation: "sign" }) if kid == id)
    );
    assert!(
        matches!(library.rec(&signing_id, &request), Err(Error::ForbiddenOperation { kid, algorithm: "ECMR", operation: "deriveKey" }) if kid == signing_id)
    );

    for request in ["{", "null", "{}"] {
        let error = library.rec(&id, request).unwrap_err();
        assert!(matches!(error, Error::InvalidRequest { .. }));
        assert!(error.source().unwrap().is::<JsonError>());
    }
    for (field, value, has_cause) in [
        ("x", json!("%%%"), true),
        ("crv", json!("P-256"), true),
        ("alg", json!("ES512"), false),
        ("key_ops", json!(["sign"]), false),
    ] {
        let mut request = vectors()[1]["request"].clone();
        request[field] = value;
        let error = library.rec(&id, &request.to_string()).unwrap_err();
        assert!(matches!(error, Error::InvalidRequest { .. }));
        assert_eq!(error.source().is_some(), has_cause);
    }
}

#[test]
fn invalid_conversion_helpers_return_typed_errors_without_private_values() {
    let secret = fixture_key(SIGNING).d.unwrap();
    for (field, value) in [
        ("x", json!("%%%")),
        ("crv", json!("P-256")),
        ("kty", json!("RSA")),
        ("d", Value::Null),
        ("d", json!("private-scalar-marker")),
        ("d", fixture_key(SECOND_SIGNING).d.unwrap().into()),
    ] {
        let mut key: Value = serde_json::from_str(SIGNING).unwrap();
        key[field] = value;
        let jwk = fixture_key(&key.to_string());
        let error = jwk.to_jwk_ec_key(false).unwrap_err();
        assert!(matches!(error, Error::InvalidKey { .. }));
        let messages = diagnostics(&error);
        assert!(!messages.contains(&secret));
        assert!(!messages.contains("private-scalar-marker"));
        if field != "d" {
            assert!(matches!(
                jwk.to_jwk_ec_key(true),
                Err(Error::InvalidKey { .. })
            ));
        }
    }
    let mut public = fixture_key(SIGNING).to_public_key();
    public.d = Some("ignored-private-scalar".into());
    assert!(public.to_jwk_ec_key(true).unwrap().is_public_key());
}

#[test]
fn error_formatting_and_sources_do_not_echo_private_json_values() {
    let library = library(&[SIGNING, RECOVERY]);
    let marker = "private-scalar-marker";
    // Serde normally quotes this value in its error: key_ops expects a list.
    let mut key: Value = serde_json::from_str(SIGNING).unwrap();
    key["key_ops"] = json!(marker);
    let json = key.to_string();
    for error in [
        TangyLib::init(KeySource::Vector(&vec![&json, RECOVERY])).unwrap_err(),
        library.rec(&thumbprint(RECOVERY), &json).unwrap_err(),
    ] {
        let messages = diagnostics(&error);
        assert!(!messages.contains(marker));
        assert!(!messages.contains(key["d"].as_str().unwrap()));
        assert!(messages.contains("JSON Data error at line"));
    }
    let formatted = format!("{library:?}");
    for source in [SIGNING, RECOVERY] {
        assert!(!formatted.contains(fixture_key(source).d.as_deref().unwrap()));
    }
}
