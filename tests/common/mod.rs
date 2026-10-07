#![allow(dead_code)]

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use tangy_lib::{KeySource, MyJwkEcKey, TangyLib};

pub const SIGNING: &str = include_str!("../fixtures/es512.json");
pub const SECOND_SIGNING: &str = include_str!("../fixtures/es512-second.json");
pub const RECOVERY: &str = include_str!("../fixtures/ecmr.json");

pub fn library(keys: &[&str]) -> TangyLib {
    TangyLib::init(KeySource::Vector(&keys.to_vec())).unwrap()
}

pub fn fixture_key(json: &str) -> MyJwkEcKey {
    serde_json::from_str(json).unwrap()
}

pub fn thumbprint(json: &str) -> String {
    fixture_key(json).thumbprint().unwrap()
}

pub fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("../fixtures/recovery.json")).unwrap()
}

pub fn decode(field: &Value) -> Vec<u8> {
    let encoded = field.as_str().unwrap();
    assert!(!encoded.contains(['=', '+', '/']), "not unpadded Base64URL");
    Base64UrlUnpadded::decode_vec(encoded).unwrap()
}

pub fn payload(adv: &Value) -> Value {
    serde_json::from_slice(&decode(&adv["payload"])).unwrap()
}

pub fn assert_public(value: &Value) {
    match value {
        Value::Object(fields) => {
            assert!(!fields.contains_key("d"), "private key in response");
            for value in fields.values() {
                assert_public(value);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_public),
        _ => {}
    }
}
