#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::todo
)]
//! Tang advertisements and P-521 message recovery with typed errors.
//!
//! ```
//! use tangy_lib::{create_new_key_set, KeySource, Result, TangyLib};
//!
//! fn initialize() -> Result<TangyLib> {
//!     let generated = create_new_key_set()?;
//!     let keys: Vec<&str> = generated.iter().map(String::as_str).collect();
//!     let server = TangyLib::init(KeySource::Vector(&keys))?;
//!     let _advertisement = server.adv(None)?;
//!     Ok(server)
//! }
//! # initialize()?;
//! # Ok::<(), tangy_lib::Error>(())
//! ```

mod error;
mod key_store;
pub use error::{
    Algorithm, Error, JsonError, KeyLocation, KeyOperation, RandomPurpose, Result, WriteStep,
};

use std::{collections::BTreeMap, path::Path};

use base64ct::{Base64UrlUnpadded, Encoding};
use p521::ecdsa::{self, signature::RandomizedSigner, SigningKey};
use p521::elliptic_curve::{self, rand_core::SeedableRng, sec1::ToSec1Point, Generate};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use sha2::Digest;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug)]
pub struct TangyLib {
    keys: BTreeMap<String, StoredKey>,
    default_adv: String,
}

// Only public JSON is retained; private material is parsed once at init.
#[derive(Debug)]
struct StoredKey {
    public: MyJwkEcKey,
    material: KeyMaterial,
    active: bool,
}

// Avoid formatting crypto private keys, including through TangyLib's Debug.
enum KeyMaterial {
    Signing(SigningKey),
    Recovery(p521::SecretKey),
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Signing(_) => "Signing([REDACTED])",
            Self::Recovery(_) => "Recovery([REDACTED])",
        })
    }
}

/// Private key inputs. Every set must have active signing and recovery keys.
#[derive(PartialEq)]
pub enum KeySource<'a> {
    /// Load `.jwk` entries; dot-prefixed filenames identify rotated keys.
    /// A genuinely empty store is initialized through locked staged publication.
    LocalDir(&'a Path),
    /// Load an entirely active slice without generating or writing keys.
    Vector(&'a [&'a str]),
    /// Load explicit active and rotated slices without persistence or generation.
    KeySets {
        active: &'a [&'a str],
        rotated: &'a [&'a str],
    },
}

impl TangyLib {
    pub fn init(source: KeySource) -> Result<Self> {
        key_store::initialize(source)
    }

    fn from_keys(keys: BTreeMap<String, StoredKey>) -> Result<Self> {
        let signing = !keys
            .values()
            .any(|key| key.active && matches!(key.material, KeyMaterial::Signing(_)));
        let recovery = !keys
            .values()
            .any(|key| key.active && matches!(key.material, KeyMaterial::Recovery(_)));
        if signing || recovery {
            return Err(Error::MissingKeys { signing, recovery });
        }
        let mut tangy = Self {
            keys,
            default_adv: String::new(),
        };
        tangy.default_adv = tangy.adv_internal(None)?;
        Ok(tangy)
    }

    pub fn adv(&self, skid: Option<&str>) -> Result<String> {
        match skid {
            None => Ok(self.default_adv.clone()),
            Some(_) => self.adv_internal(skid),
        }
    }

    pub fn adv_internal(&self, skid: Option<&str>) -> Result<String> {
        self.adv_with_rng(skid, &mut getrandom::fill)
    }

    fn adv_with_rng<E: std::error::Error + Send + Sync + 'static>(
        &self,
        skid: Option<&str>,
        entropy: &mut impl FnMut(&mut [u8]) -> std::result::Result<(), E>,
    ) -> Result<String> {
        #[derive(Serialize)]
        struct Signature {
            protected: String,
            signature: String,
        }
        #[derive(Serialize)]
        struct Advertise {
            payload: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            protected: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            signature: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            signatures: Option<Vec<Signature>>,
        }
        #[derive(Serialize)]
        struct Payload<'a> {
            keys: Vec<&'a MyJwkEcKey>,
        }

        if let Some(kid) = skid {
            let key = self
                .keys
                .get(kid)
                .ok_or_else(|| Error::KeyNotFound { kid: kid.into() })?;
            if !matches!(key.material, KeyMaterial::Signing(_)) {
                return Err(Error::ForbiddenOperation {
                    kid: kid.into(),
                    algorithm: Algorithm::Es512,
                    operation: KeyOperation::Sign,
                });
            }
        }

        let payload = Base64UrlUnpadded::encode_string(&serialize(
            &Payload {
                keys: self
                    .keys
                    .values()
                    .filter(|key| key.active)
                    .map(|key| &key.public)
                    .collect(),
            },
            "advertisement payload",
        )?);
        let protected =
            Base64UrlUnpadded::encode_string(r#"{"alg":"ES512","cty":"jwk-set+json"}"#.as_bytes());
        let to_sign = format!("{protected}.{payload}");
        let mut rng = crypto_rng(entropy, RandomPurpose::AdvertisementSigning)?;
        // Like Tang, retain signatures for every advertised verification key.
        let mut signatures = Vec::new();
        for (kid, key) in &self.keys {
            if !key.active && skid != Some(kid.as_str()) {
                continue;
            }
            if let KeyMaterial::Signing(signing) = &key.material {
                let signature: ecdsa::Signature = signing
                    .try_sign_with_rng(&mut rng, to_sign.as_bytes())
                    .map_err(|source| Error::Signing {
                        kid: kid.clone(),
                        source: Box::new(source),
                    })?;
                signatures.push(Signature {
                    protected: protected.clone(),
                    signature: Base64UrlUnpadded::encode_string(&signature.to_bytes()),
                });
            }
        }
        // Initialization guarantees at least one signing key.
        let advertisement = match signatures.as_slice() {
            [signature] => Advertise {
                payload,
                protected: Some(signature.protected.clone()),
                signature: Some(signature.signature.clone()),
                signatures: None,
            },
            _ => Advertise {
                payload,
                protected: None,
                signature: None,
                signatures: Some(signatures),
            },
        };
        serialize_string(&advertisement, "advertisement")
    }

    pub fn rec(&self, kid: &str, request: &str) -> Result<String> {
        let key = self
            .keys
            .get(kid)
            .ok_or_else(|| Error::KeyNotFound { kid: kid.into() })?;
        let secret = match &key.material {
            KeyMaterial::Recovery(secret) => secret,
            KeyMaterial::Signing(_) => {
                return Err(Error::ForbiddenOperation {
                    kid: kid.into(),
                    algorithm: Algorithm::Ecmr,
                    operation: KeyOperation::DeriveKey,
                })
            }
        };
        let request_key = parse_private_jwk(request)
            .map_err(|source| Error::request_cause("invalid JSON", JsonError(source)))?;
        if request_key.alg.as_deref().is_some_and(|alg| alg != "ECMR") {
            return Err(Error::request("algorithm must be ECMR"));
        }
        if request_key
            .key_ops
            .as_ref()
            .is_some_and(|ops| !ops.iter().any(|op| op == "deriveKey"))
        {
            return Err(Error::request("key operations must permit deriveKey"));
        }
        let request_key = request_key
            .to_p521_public_key()
            .map_err(|source| Error::request_cause("invalid public key", source))?;
        let response =
            diffie_hellman_public_key(&secret.to_nonzero_scalar(), request_key.as_affine())?;
        serialize_string(&response, "recovery response")
    }
}

/// Generate private signing and recovery JWKs without writing files.
/// OS entropy and serialization failures are returned to the caller.
pub fn create_new_key_set() -> Result<Vec<String>> {
    create_new_key_set_with_rng(&mut getrandom::fill)
}

fn create_new_key_set_with_rng<E: std::error::Error + Send + Sync + 'static>(
    entropy: &mut impl FnMut(&mut [u8]) -> std::result::Result<(), E>,
) -> Result<Vec<String>> {
    let mut rng = crypto_rng(entropy, RandomPurpose::KeyGeneration)?;
    let mut signing = Zeroizing::new(create_new_jwk("ES512", &["sign", "verify"], &mut rng)?);
    let mut recovery = Zeroizing::new(create_new_jwk("ECMR", &["deriveKey"], &mut rng)?);
    Ok(vec![
        std::mem::take(&mut *signing),
        std::mem::take(&mut *recovery),
    ])
}

// Seed a fresh CSPRNG through a fallible OS call before crypto operations.
// ChaCha20 fills cannot fail; entropy failures retain their original source and
// operation context, including before randomized signing.
fn crypto_rng<E: std::error::Error + Send + Sync + 'static>(
    entropy: &mut impl FnMut(&mut [u8]) -> std::result::Result<(), E>,
    operation: RandomPurpose,
) -> Result<ChaCha20Rng> {
    let mut seed = Zeroizing::new([0u8; 32]);
    entropy(seed.as_mut()).map_err(|source| Error::Randomness {
        operation,
        source: Box::new(source),
    })?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

fn serialize<T: Serialize>(value: &T, context: &'static str) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|source| Error::Serialization { context, source })
}

fn serialize_string<T: Serialize>(value: &T, context: &'static str) -> Result<String> {
    serde_json::to_string(value).map_err(|source| Error::Serialization { context, source })
}

fn require_operation(
    key: &MyJwkEcKey,
    kid: &str,
    algorithm: Algorithm,
    operation: KeyOperation,
) -> Result<()> {
    if key.alg.as_deref() != Some(algorithm.as_str())
        || !key
            .key_ops
            .as_ref()
            .is_some_and(|ops| ops.iter().any(|op| op == operation.as_str()))
    {
        return Err(Error::ForbiddenOperation {
            kid: kid.into(),
            algorithm,
            operation,
        });
    }
    Ok(())
}

fn parse_stored_key(json: &str) -> Result<Zeroizing<MyJwkEcKey>> {
    parse_private_jwk(json).map_err(|source| Error::key_cause("invalid JSON", JsonError(source)))
}

fn validate_stored_key(jwk: Zeroizing<MyJwkEcKey>, kid: &str) -> Result<StoredKey> {
    match jwk.alg.as_deref() {
        Some("ES512") => {
            require_operation(&jwk, kid, Algorithm::Es512, KeyOperation::Sign)?;
            require_operation(&jwk, kid, Algorithm::Es512, KeyOperation::Verify)?;
        }
        Some("ECMR") => require_operation(&jwk, kid, Algorithm::Ecmr, KeyOperation::DeriveKey)?,
        _ => return Err(Error::invalid_key("algorithm must be ES512 or ECMR")),
    }
    let secret = jwk.to_p521_secret_key()?;
    let material = if jwk.alg.as_deref() == Some("ES512") {
        KeyMaterial::Signing(SigningKey::from(&secret))
    } else {
        KeyMaterial::Recovery(secret)
    };
    let mut public = jwk.to_public_key();
    if let Some(ops) = &mut public.key_ops {
        ops.retain(|op| op != "sign");
    }
    Ok(StoredKey {
        public,
        material,
        active: true,
    })
}

fn create_new_jwk(alg: &str, key_ops: &[&str], rng: &mut ChaCha20Rng) -> Result<String> {
    let secret = p521::SecretKey::generate_from_rng(rng);
    let mut jwk = Zeroizing::new(format_public_key(&secret.public_key())?);
    jwk.d = Some(Base64UrlUnpadded::encode_string(&Zeroizing::new(
        secret.to_bytes(),
    )));
    jwk.alg = Some(alg.into());
    jwk.key_ops = Some(key_ops.iter().map(|op| (*op).into()).collect());
    serialize_string(&*jwk, "generated private key")
}

fn format_public_key(public: &p521::PublicKey) -> Result<MyJwkEcKey> {
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

fn diffie_hellman_public_key(
    secret_key: &elliptic_curve::NonZeroScalar<p521::NistP521>,
    public_key: &elliptic_curve::AffinePoint<p521::NistP521>,
) -> Result<MyJwkEcKey> {
    let public_point = p521::ProjectivePoint::from(*public_key);
    let secret_point = (public_point * secret_key.as_ref()).to_affine();
    // A validated nonidentity point times a nonzero scalar on the prime-order
    // P-521 curve cannot be the identity. Retain a request-classified error at
    // this fallible API boundary in case that invariant ever changes.
    let public = p521::PublicKey::from_affine(secret_point)
        .map_err(|source| Error::request_cause("invalid recovery result point", source))?;
    let mut jwk = format_public_key(&public)?;
    jwk.alg = Some("ECMR".into());
    jwk.key_ops = Some(vec!["deriveKey".into()]);
    Ok(jwk)
}

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

    /// Key Type (must be "EC" if present) as described in RFC 7517 4.1:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.1>
    ///
    /// Value is optional.
    ///
    /// For Elliptic-Curve the value must be "EC".
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

    /// The X.509 Certificate SHA-256 as described in RFC 7517 4.9:
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

fn parse_private_jwk(json: &str) -> std::result::Result<Zeroizing<MyJwkEcKey>, serde_json::Error> {
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

    /// Compute an RFC 7638 thumbprint from the public fields.
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::todo
)]
mod tests {
    use super::*;
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
}
