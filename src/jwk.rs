// SPDX-License-Identifier: MIT OR Apache-2.0

//! Translate between JSON Web Keys (JWKs) and typed P-521 cryptographic keys.
//!
//! Tang stores keys and exchanges public points as JavaScript Object Notation
//! (JSON). This module owns that representation, its field encoding and its key
//! identities, so key storage and protocol responses use the same conversions.
//! File loading and persistence belong to the key-store module; advertisement
//! signing and recovery calculations belong to the protocol module.
//!
//! [`MyJwkEcKey`] holds public coordinates (`x` and `y`), an optional private
//! scalar (`d`) and metadata describing the key. Deserialization checks the JSON
//! structure. The typed conversion methods check the cryptographic material:
//! `kty` must be `EC`, `crv` must be `P-521`, and coordinates must be valid curve
//! points encoded as exactly 66 bytes each using URL-safe Base64 without padding.
//! Public conversion ignores `d`. Private conversion also requires a 66-byte,
//! nonzero scalar below the curve order whose public point matches `x` and `y`.
//! Key-role rules for `alg` and `key_ops` are enforced by the key-store and
//! protocol modules when they accept keys for a particular operation.
//!
//! [`create_new_key_set`] generates two private JWK strings: an `ES512` signing
//! key permitting `sign` and `verify`, and an elliptic-curve message recovery
//! (`ECMR`) key permitting `deriveKey`. It obtains randomness through the shared
//! fallible seeding helper and returns the strings for callers to store or load.
//!
//! [`MyJwkEcKey::thumbprint`] computes the key identity used throughout the
//! library. Following RFC 7638, it serializes only `crv`, `kty`, `x` and `y` in
//! that order, hashes the JSON with SHA-256 and encodes the digest as URL-safe
//! Base64 without padding. Private material and optional metadata therefore do
//! not change the identity. Thumbprinting hashes the supplied fields; key
//! validation happens through the typed conversions described above.
//!
//! [`MyJwkEcKey::to_public_key`] copies public fields and metadata while omitting
//! `d`, and debug formatting redacts `d`. Internal parsing, decoding and generation
//! use zeroizing wrappers for private scalar temporaries. The public struct and
//! generated strings remain caller-owned; those values are not automatically
//! erased when dropped.

use base64ct::{Base64UrlUnpadded, Encoding};
use p521::elliptic_curve::{sec1::ToSec1Point, Generate};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use sha2::Digest;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    support::{crypto_rng, serialize, serialize_string},
    Algorithm, Error, KeyOperation, RandomPurpose, Result,
};

/// Generate private signing and recovery JWKs without writing files.
/// Operating-system entropy and serialization failures are returned to the caller.
pub fn create_new_key_set() -> Result<Vec<String>> {
    create_new_key_set_with_rng(&mut getrandom::fill)
}

pub(crate) fn create_new_key_set_with_rng<E: std::error::Error + Send + Sync + 'static>(
    entropy: &mut impl FnMut(&mut [u8]) -> std::result::Result<(), E>,
) -> Result<Vec<String>> {
    let mut rng = crypto_rng(entropy, RandomPurpose::KeyGeneration)?;
    let mut signing = Zeroizing::new(create_new_jwk(Algorithm::Es512, &mut rng)?);
    let mut recovery = Zeroizing::new(create_new_jwk(Algorithm::Ecmr, &mut rng)?);
    Ok(vec![
        std::mem::take(&mut *signing),
        std::mem::take(&mut *recovery),
    ])
}

fn create_new_jwk(algorithm: Algorithm, rng: &mut ChaCha20Rng) -> Result<String> {
    let key_ops: &[KeyOperation] = match algorithm {
        Algorithm::Es512 => &[KeyOperation::Sign, KeyOperation::Verify],
        Algorithm::Ecmr => &[KeyOperation::DeriveKey],
    };
    let secret = p521::SecretKey::generate_from_rng(rng);
    let mut jwk = Zeroizing::new(format_public_key(&secret.public_key())?);
    jwk.d = Some(Base64UrlUnpadded::encode_string(&Zeroizing::new(
        secret.to_bytes(),
    )));
    jwk.alg = Some(algorithm.as_str().into());
    jwk.key_ops = Some(key_ops.iter().map(|op| op.as_str().into()).collect());
    serialize_string(&*jwk, "generated private key")
}

pub(crate) fn format_public_key(public: &p521::PublicKey) -> Result<MyJwkEcKey> {
    let point = public.to_sec1_point(false);
    let x = point
        .x()
        .ok_or_else(|| Error::invalid_key("public point has no x coordinate"))?;
    let y = point
        .y()
        .ok_or_else(|| Error::invalid_key("public point has no y coordinate"))?;
    Ok(MyJwkEcKey {
        alg: None,
        kty: "EC".into(),
        crv: "P-521".into(),
        x: Base64UrlUnpadded::encode_string(x),
        y: Base64UrlUnpadded::encode_string(y),
        d: None,
        key_ops: None,
        use_: None,
        kid: None,
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    })
}

/// An elliptic-curve JSON Web Key. Deserialization alone does not validate key material.
/// Use the typed conversion methods to validate P-521 coordinates and scalars.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct MyJwkEcKey {
    /// The `crv` parameter which identifies a particular elliptic curve
    /// as defined in RFC 7518 Section 6.2.1.1:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.1>
    pub crv: String,

    /// The x-coordinate of the elliptic curve point which is the public key
    /// value associated with this JWK as defined in RFC 7518 6.2.1.2:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.2>
    pub x: String,

    /// The y-coordinate of the elliptic curve point which is the public key
    /// value associated with this JWK as defined in RFC 7518 6.2.1.3:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.3>
    pub y: String,

    /// The `d` ECC private key parameter as described in RFC 7518 6.2.2.1:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.2.1>
    ///
    /// Value is optional and if omitted, this JWK represents a public key.
    ///
    /// Inner value is encoded according to the `Integer-to-Octet-String`
    /// conversion as defined in SEC1 section 2.3.7:
    /// <https://www.secg.org/sec1-v2.pdf>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    /// Required Key Type (must be "EC") as described in RFC 7517 4.1:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.1>
    ///
    /// Required for deserialization and P-521 conversion.
    pub kty: String,

    /// The Public Key Use as described in RFC 7517 4.2:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none", rename = "use")]
    pub use_: Option<String>,

    /// The Key Operations as described in RFC 7517 4.3:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.3>
    ///
    /// Stored keys require appropriate operations. Recovery requests may omit
    /// this field, but explicit operations must permit derivation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    /// The Algorithm as described in RFC 7517 4.4:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.4>
    ///
    /// Stored keys must use ES512 or ECMR. Recovery requests may omit this field,
    /// but an explicit algorithm must be ECMR.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// The Key ID as described in RFC 7517 4.5:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.5>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// The X.509 URL as described in RFC 7517 4.6:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.6>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// The X.509 Certificate Chain as described in RFC 7517 4.7:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.7>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    /// The X.509 Certificate SHA-1 Thumbprint as described in RFC 7517 4.8:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.8>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// The X.509 Certificate SHA-256 Thumbprint as described in RFC 7517 4.9:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.9>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

impl std::fmt::Debug for MyJwkEcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MyJwkEcKey")
            .field("crv", &self.crv)
            .field("kty", &self.kty)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("alg", &self.alg)
            .field("key_ops", &self.key_ops)
            .field("use", &self.use_)
            .field("kid", &self.kid)
            .field("x5u", &self.x5u)
            .field("x5c", &self.x5c)
            .field("x5t", &self.x5t)
            .field("x5t_s256", &self.x5t_s256)
            .field("d", &self.d.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl Zeroize for MyJwkEcKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

pub(crate) fn parse_private_jwk(
    json: &str,
) -> std::result::Result<Zeroizing<MyJwkEcKey>, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct Fields {
        crv: String,
        x: String,
        y: String,
        kty: String,
        d: Option<Zeroizing<String>>,
        #[serde(rename = "use")]
        use_: Option<String>,
        key_ops: Option<Vec<String>>,
        alg: Option<String>,
        kid: Option<String>,
        x5u: Option<String>,
        x5c: Option<String>,
        x5t: Option<String>,
        x5t_s256: Option<String>,
    }
    let mut fields: Fields = serde_json::from_str(json)?;
    Ok(Zeroizing::new(MyJwkEcKey {
        crv: fields.crv,
        x: fields.x,
        y: fields.y,
        kty: fields.kty,
        d: fields.d.as_mut().map(|d| std::mem::take(&mut **d)),
        use_: fields.use_,
        key_ops: fields.key_ops,
        alg: fields.alg,
        kid: fields.kid,
        x5u: fields.x5u,
        x5c: fields.x5c,
        x5t: fields.x5t,
        x5t_s256: fields.x5t_s256,
    }))
}

// Fixed-size decoding bounds allocations and zeroizes partial private output
// on every failure path. Never attach input values to diagnostics.
fn decode_jwk_field(value: &str) -> Result<Zeroizing<[u8; 66]>> {
    let mut bytes = Zeroizing::new([0u8; 66]);
    let decoded = Base64UrlUnpadded::decode(value, bytes.as_mut())
        .map_err(|source| Error::key_cause("invalid JWK field encoding", source))?;
    if decoded.len() != 66 {
        return Err(Error::invalid_key(
            "JWK fields must encode exactly 66 bytes",
        ));
    }
    Ok(bytes)
}

impl MyJwkEcKey {
    /// Validate and convert the public coordinates of a P-521 JWK.
    /// Coordinates must be unpadded Base64URL encoding exactly 66 bytes each.
    /// The private scalar, if present, is ignored.
    pub fn to_p521_public_key(&self) -> Result<p521::PublicKey> {
        if self.kty != "EC" {
            return Err(Error::invalid_key("key type must be EC"));
        }
        if self.crv != "P-521" {
            return Err(Error::invalid_key("curve must be P-521"));
        }
        let x = decode_jwk_field(&self.x)?;
        let y = decode_jwk_field(&self.y)?;
        let encoded: Vec<u8> = std::iter::once(4)
            .chain(x.iter().copied())
            .chain(y.iter().copied())
            .collect();
        p521::PublicKey::from_sec1_bytes(&encoded)
            .map_err(|source| Error::key_cause("invalid public point", source))
    }

    /// Validate and convert a P-521 private JWK, including its public point.
    /// The private scalar must encode exactly 66 bytes in unpadded Base64URL,
    /// be nonzero and below the curve order, and match the public coordinates.
    ///
    /// ```
    /// use tangy_lib::{create_new_key_set, MyJwkEcKey};
    ///
    /// for json in create_new_key_set()? {
    ///     let jwk: MyJwkEcKey = serde_json::from_str(&json)?;
    ///     let secret = jwk.to_p521_secret_key()?;
    ///     let public = jwk.to_p521_public_key()?;
    ///     assert_eq!(secret.public_key(), public);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn to_p521_secret_key(&self) -> Result<p521::SecretKey> {
        let public = self.to_p521_public_key()?;
        let d = self
            .d
            .as_deref()
            .ok_or_else(|| Error::invalid_key("private scalar is missing"))?;
        let bytes = decode_jwk_field(d)?;
        let secret = p521::SecretKey::from_slice(bytes.as_ref())
            .map_err(|source| Error::key_cause("invalid private scalar", source))?;
        if secret.public_key() != public {
            return Err(Error::invalid_key(
                "private scalar does not match public point",
            ));
        }
        Ok(secret)
    }

    /// Copy the JWK fields while omitting the private scalar.
    /// This projection does not validate the key or change its operation metadata.
    pub fn to_public_key(&self) -> MyJwkEcKey {
        Self {
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            d: None,
            kty: self.kty.clone(),
            use_: self.use_.clone(),
            key_ops: self.key_ops.clone(),
            alg: self.alg.clone(),
            kid: self.kid.clone(),
            x5u: self.x5u.clone(),
            x5c: self.x5c.clone(),
            x5t: self.x5t.clone(),
            x5t_s256: self.x5t_s256.clone(),
        }
    }

    /// Compute a SHA-256 RFC 7638 thumbprint from the required public fields.
    /// Private material and optional metadata do not affect the identity.
    /// This hashes the supplied fields without validating their key material.
    pub fn thumbprint(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Required<'a> {
            crv: &'a str,
            kty: &'a str,
            x: &'a str,
            y: &'a str,
        }
        let fields = Required {
            crv: &self.crv,
            kty: &self.kty,
            x: &self.x,
            y: &self.y,
        };
        Ok(Base64UrlUnpadded::encode_string(&sha2::Sha256::digest(
            serialize(&fields, "key thumbprint")?,
        )))
    }
}
