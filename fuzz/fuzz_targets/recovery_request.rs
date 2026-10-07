#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tangy_lib::{Error, KeySource, MyJwkEcKey, TangyLib};

fn server() -> &'static (TangyLib, String) {
    static SERVER: OnceLock<(TangyLib, String)> = OnceLock::new();
    SERVER.get_or_init(|| {
        let signing = include_str!("../../tests/fixtures/es512.json");
        let recovery = include_str!("../../tests/fixtures/ecmr.json");
        let key: MyJwkEcKey = serde_json::from_str(recovery).expect("valid test fixture");
        (
            TangyLib::init(KeySource::Vector(&[signing, recovery])).expect("valid test key set"),
            key.thumbprint().expect("fixture thumbprint"),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = std::str::from_utf8(data) {
        let (server, kid) = server();
        match server.rec(kid, request) {
            Ok(response) => {
                let key: MyJwkEcKey = serde_json::from_str(&response).expect("valid response JSON");
                assert!(key.d.is_none());
                assert_eq!(key.alg.as_deref(), Some("ECMR"));
                assert_eq!(key.key_ops.as_deref(), Some(&["deriveKey".into()][..]));
                assert!(key.to_p521_public_key().is_ok());
            }
            // A known recovery key and in-memory response leave only client input errors.
            Err(error) => assert!(matches!(error, Error::InvalidRequest { .. })),
        }
    }
});
