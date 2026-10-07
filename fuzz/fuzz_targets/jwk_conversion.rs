#![no_main]

use base64ct::{Base64UrlUnpadded, Encoding};
use libfuzzer_sys::fuzz_target;
use tangy_lib::MyJwkEcKey;

fn check(key: MyJwkEcKey) {
    let public = key.to_p521_public_key();
    if let Ok(secret) = key.to_p521_secret_key() {
        assert_eq!(
            public.as_ref().expect("valid private key has public point"),
            &secret.public_key()
        );
    }
    let projected = key.to_public_key();
    assert!(projected.d.is_none());
    assert_eq!(key.thumbprint().unwrap(), projected.thumbprint().unwrap());
    let mut altered = key;
    altered.d = Some("invalid private scalar".into());
    assert_eq!(public.ok(), altered.to_p521_public_key().ok());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = serde_json::from_slice::<MyJwkEcKey>(data) {
        check(key);
    }
    // Also reach conversion with structurally valid JSON on every iteration.
    // Variable lengths exercise both fixed-width decoding and scalar validation.
    let mut key: MyJwkEcKey =
        serde_json::from_str(include_str!("../../tests/fixtures/es512.json")).unwrap();
    match data.first().copied().unwrap_or_default() % 3 {
        0 => key.x = Base64UrlUnpadded::encode_string(data.get(1..).unwrap_or_default()),
        1 => key.y = Base64UrlUnpadded::encode_string(data.get(1..).unwrap_or_default()),
        _ => {
            key.d = Some(Base64UrlUnpadded::encode_string(
                data.get(1..).unwrap_or_default(),
            ))
        }
    }
    check(key);
});
