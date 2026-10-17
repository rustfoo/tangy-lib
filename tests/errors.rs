mod common;

use std::error::Error as StdError;

use common::*;
use serde_json::{json, Value};
use tangy_lib::{
    Algorithm, Error, JsonError, KeyLocation, KeyOperation, KeySource, RandomPurpose, TangyLib,
    WriteStep,
};

fn diagnostics(error: &dyn StdError) -> String {
    let mut messages = format!("{error} {error:?}");
    let mut source = error.source();
    while let Some(error) = source {
        messages.push_str(&format!(" {error} {error:?}"));
        source = error.source();
    }
    messages
}

/// Assures: KEY-LOAD-001, ERR-DIAG-001
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

/// Assures: ERR-DIAG-001
#[test]
fn invalid_stored_keys_include_their_origin_and_safe_source_chain() {
    let error = TangyLib::init(KeySource::Vector(&[SIGNING, RECOVERY, "{"])).unwrap_err();
    assert!(matches!(
        &error,
        Error::InvalidStoredKey {
            location: KeyLocation::Input(2),
            ..
        }
    ));
    let Error::InvalidStoredKey { source, .. } = &error else {
        panic!("unexpected error: {error:?}");
    };
    let invalid = source.as_ref();
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

/// Assures: ERR-DIAG-001
#[test]
fn stored_policy_and_crypto_errors_retain_validation_causes() {
    let mut key: Value = serde_json::from_str(SIGNING).unwrap();
    key["key_ops"] = json!(["verify"]);
    let invalid = key.to_string();
    let error = TangyLib::init(KeySource::Vector(&[RECOVERY, &invalid])).unwrap_err();
    assert!(matches!(
        &error,
        Error::InvalidStoredKey {
            location: KeyLocation::Input(1),
            ..
        }
    ));
    let Error::InvalidStoredKey { source, .. } = &error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(matches!(
        source.as_ref(),
        Error::ForbiddenOperation { kid, algorithm: Algorithm::Es512, operation: KeyOperation::Sign } if kid == &thumbprint(SIGNING)
    ));

    key["key_ops"] = json!(["sign", "verify"]);
    key["x"] = json!("%%%");
    let invalid = key.to_string();
    let error = TangyLib::init(KeySource::Vector(&[RECOVERY, &invalid])).unwrap_err();
    let Error::InvalidStoredKey { source, .. } = &error else {
        panic!("unexpected error: {error:?}");
    };
    let validation = source.as_ref();
    assert!(matches!(validation, Error::InvalidKey { .. }));
    assert!(validation.source().unwrap().is::<elliptic_curve::Error>());
}

/// Assures: ERR-DIAG-001
#[test]
fn stored_policy_errors_identify_every_required_operation() {
    for (fixture, operations, algorithm, operation) in [
        (
            SIGNING,
            json!(["verify"]),
            Algorithm::Es512,
            KeyOperation::Sign,
        ),
        (
            SIGNING,
            json!(["sign"]),
            Algorithm::Es512,
            KeyOperation::Verify,
        ),
        (
            RECOVERY,
            json!([]),
            Algorithm::Ecmr,
            KeyOperation::DeriveKey,
        ),
    ] {
        let mut key: Value = serde_json::from_str(fixture).unwrap();
        key["key_ops"] = operations;
        let invalid = key.to_string();
        let error = TangyLib::init(KeySource::Vector(&[invalid.as_str()])).unwrap_err();
        let Error::InvalidStoredKey { location, source } = &error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(location, &KeyLocation::Input(0));
        assert!(matches!(source.as_ref(), Error::ForbiddenOperation {
            kid, algorithm: actual_algorithm, operation: actual_operation,
        } if kid == &thumbprint(fixture) && *actual_algorithm == algorithm && *actual_operation == operation));
    }
}

/// Assures: ERR-DIAG-001
#[test]
fn operation_displays_preserve_protocol_and_diagnostic_wording() {
    for (actual, expected) in [
        (Algorithm::Es512.to_string(), "ES512"),
        (Algorithm::Ecmr.to_string(), "ECMR"),
        (KeyOperation::Sign.to_string(), "sign"),
        (KeyOperation::Verify.to_string(), "verify"),
        (KeyOperation::DeriveKey.to_string(), "deriveKey"),
        (WriteStep::Create.to_string(), "create"),
        (WriteStep::Write.to_string(), "write"),
        (WriteStep::Synchronize.to_string(), "synchronize"),
        (WriteStep::Publish.to_string(), "publish"),
        (
            KeyLocation::RotatedInput(2).to_string(),
            "rotated input index 2",
        ),
        (RandomPurpose::KeyGeneration.to_string(), "key generation"),
        (
            RandomPurpose::AdvertisementSigning.to_string(),
            "advertisement signing",
        ),
        (KeyLocation::Input(2).to_string(), "input index 2"),
    ] {
        assert_eq!(actual, expected);
    }
}

/// Assures: ERR-DIAG-001
#[test]
fn top_level_messages_exclude_sources_and_chains_report_each_cause_once() {
    let cause = || std::io::Error::other("source-marker");
    let errors = [
        Error::InvalidStoredKey {
            location: KeyLocation::Input(2),
            source: Box::new(Error::InvalidKey {
                reason: "validation-marker",
                source: Some(Box::new(cause())),
            }),
        },
        Error::InvalidKey {
            reason: "bad key",
            source: Some(Box::new(cause())),
        },
        Error::InvalidRequest {
            reason: "bad request",
            source: Some(Box::new(cause())),
        },
        Error::KeyDirectory {
            path: "keys".into(),
            source: cause(),
        },
        Error::KeyRead {
            path: "keys/key.jwk".into(),
            source: cause(),
        },
        Error::KeyWrite {
            path: "keys/key.jwk".into(),
            operation: WriteStep::Write,
            source: cause(),
        },
        Error::Serialization {
            context: "test payload",
            source: <serde_json::Error as serde::ser::Error>::custom("source-marker"),
        },
        Error::Signing {
            kid: "key-id".into(),
            source: Box::new(cause()),
        },
        Error::Randomness {
            operation: RandomPurpose::KeyGeneration,
            source: Box::new(cause()),
        },
    ];
    for error in errors {
        let top_level = error.to_string();
        let mut chain = top_level.clone();
        let mut source = error.source();
        while let Some(cause) = source {
            let message = cause.to_string();
            assert!(!top_level.contains(&message), "source repeated in {error}");
            chain.push_str(&format!("\ncaused by: {cause}"));
            source = cause.source();
        }
        assert_eq!(chain.matches("source-marker").count(), 1, "{chain}");
        if matches!(error, Error::InvalidStoredKey { .. }) {
            assert_eq!(top_level, "invalid stored key at input index 2");
            assert_eq!(chain.matches("validation-marker").count(), 1, "{chain}");
        }
    }
}

/// Assures: ERR-DIAG-001
#[test]
fn signing_failures_retain_the_key_id_and_opaque_crypto_cause() {
    let error = Error::Signing {
        kid: "signing-key-id".into(),
        source: Box::new(p521::ecdsa::signature::Error::new()),
    };
    assert!(matches!(&error, Error::Signing { kid, .. } if kid == "signing-key-id"));
    assert!(error
        .source()
        .unwrap()
        .is::<p521::ecdsa::signature::Error>());
}

/// Assures: ERR-DIAG-001
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

/// Assures: REQ-REJECT-001, ERR-DIAG-001
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
        matches!(library.adv(Some(&id)), Err(Error::ForbiddenOperation { kid, algorithm: Algorithm::Es512, operation: KeyOperation::Sign }) if kid == id)
    );
    assert!(
        matches!(library.rec(&signing_id, &request), Err(Error::ForbiddenOperation { kid, algorithm: Algorithm::Ecmr, operation: KeyOperation::DeriveKey }) if kid == signing_id)
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

/// Assures: KEY-PRIV-001
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

/// Assures: KEY-PRIV-001
#[test]
fn error_formatting_and_sources_do_not_echo_private_json_values() {
    let library = library(&[SIGNING, RECOVERY]);
    let marker = "private-scalar-marker";
    // Serde normally quotes this value in its error: key_ops expects a list.
    let mut key: Value = serde_json::from_str(SIGNING).unwrap();
    key["key_ops"] = json!(marker);
    let json = key.to_string();
    for error in [
        TangyLib::init(KeySource::Vector(&[&json, RECOVERY])).unwrap_err(),
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
