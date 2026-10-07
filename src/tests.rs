// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::*;
use crate::{
    jwk::create_new_key_set_with_rng,
    key_store::parse_stored_key,
    support::{serialize, serialize_string},
};
use serde::Serialize;
use std::{error::Error as _, io};

fn failing_entropy(_dest: &mut [u8]) -> std::result::Result<(), io::Error> {
    Err(io::Error::other("injected entropy failure"))
}

/// Assures: KEY-GEN-001
#[test]
fn entropy_failures_return_errors_before_key_generation_or_signing() {
    let error = create_new_key_set_with_rng(&mut failing_entropy).unwrap_err();
    assert!(matches!(
        error,
        Error::Randomness {
            operation: RandomPurpose::KeyGeneration,
            ..
        }
    ));
    assert!(error.source().unwrap().is::<io::Error>());
    assert_eq!(
        error.source().unwrap().to_string(),
        "injected entropy failure"
    );

    let keys = vec![
        include_str!("../tests/fixtures/es512.json"),
        include_str!("../tests/fixtures/ecmr.json"),
    ];
    let library = TangyLib::init(KeySource::Vector(&keys)).unwrap();
    for selection in [None, Some(keys[0])]
        .map(|key| key.map(|key| parse_stored_key(key).unwrap().thumbprint().unwrap()))
    {
        let error = library
            .adv_with_rng(selection.as_deref(), &mut failing_entropy)
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Randomness {
                operation: RandomPurpose::AdvertisementSigning,
                ..
            }
        ));
        assert!(error.source().unwrap().is::<io::Error>());
        assert_eq!(
            error.source().unwrap().to_string(),
            "injected entropy failure"
        );
    }
    // Serving the cached advertisement requires no new entropy.
    assert!(!library.adv(None).unwrap().is_empty());
}

/// Assures: ERR-DIAG-001
#[test]
fn serialization_failures_keep_their_context_and_cause() {
    struct Unserializable;
    impl Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(
            &self,
            _serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("injected serialization failure"))
        }
    }
    for error in [
        serialize(&Unserializable, "test payload").unwrap_err(),
        serialize_string(&Unserializable, "test response").unwrap_err(),
    ] {
        assert!(matches!(error, Error::Serialization { .. }));
        assert_eq!(
            error.source().unwrap().to_string(),
            "injected serialization failure"
        );
    }
}
