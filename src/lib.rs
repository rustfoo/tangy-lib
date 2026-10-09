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
pub use error::{
    Algorithm, Error, JsonError, KeyLocation, KeyOperation, RandomPurpose, Result, WriteStep,
};

use std::{
    collections::HashMap,
    fs::File,
    io::{self, Write},
    path::Path,
    str::FromStr,
};

use base64ct::{Base64UrlUnpadded, Encoding};
use elliptic_curve::{
    rand_core::{CryptoRngCore, OsRng, SeedableRng},
    sec1::ToEncodedPoint,
    JwkEcKey,
};
use p521::ecdsa::{self, signature::RandomizedSigner, SigningKey};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use sha2::Digest;

#[derive(Debug)]
pub struct TangyLib {
    keys: HashMap<String, StoredKey>,
    default_adv: String,
}

// Only public JSON is retained; private material is parsed once at init.
#[derive(Debug)]
struct StoredKey {
    public: MyJwkEcKey,
    material: KeyMaterial,
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

#[derive(PartialEq)]
pub enum KeySource<'a> {
    LocalDir(&'a Path),
    Vector(&'a Vec<&'a str>),
}

impl TangyLib {
    pub fn init(source: KeySource) -> Result<Self> {
        Self::init_with_key_writer(source, create_key_file)
    }

    // Keep the file-opening boundary injectable so write failures can be tested
    // on every platform, including when tests run with elevated privileges.
    fn init_with_key_writer<W: Write>(
        source: KeySource,
        mut create: impl FnMut(&Path) -> io::Result<W>,
    ) -> Result<Self> {
        let mut loaded_keys = match source {
            KeySource::LocalDir(dir) => load_keys_from_dir(dir)?,
            KeySource::Vector(keys) => load_keys_from_vec(keys)?,
        };

        if loaded_keys.is_empty() {
            if let KeySource::LocalDir(dir) = source {
                for json in create_new_key_set()? {
                    let jwk = parse_stored_key(&json)?;
                    let kid = jwk.thumbprint()?;
                    let key = validate_stored_key(jwk, &kid)?;
                    let path = dir.join(format!("{kid}.jwk"));
                    let mut file = create(&path).map_err(|source| Error::KeyWrite {
                        path: path.clone(),
                        operation: WriteStep::Create,
                        source,
                    })?;
                    file.write_all(json.as_bytes())
                        .map_err(|source| Error::KeyWrite {
                            path,
                            operation: WriteStep::Write,
                            source,
                        })?;
                    loaded_keys.insert(kid, key);
                }
            }
        }

        let signing = !loaded_keys
            .values()
            .any(|key| matches!(key.material, KeyMaterial::Signing(_)));
        let recovery = !loaded_keys
            .values()
            .any(|key| matches!(key.material, KeyMaterial::Recovery(_)));
        if signing || recovery {
            return Err(Error::MissingKeys { signing, recovery });
        }
        let mut tangy = Self {
            keys: loaded_keys,
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
        self.adv_with_rng(skid, &mut OsRng)
    }

    fn adv_with_rng(&self, skid: Option<&str>, entropy: &mut impl CryptoRngCore) -> Result<String> {
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
                keys: self.keys.values().map(|key| &key.public).collect(),
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
        let request_key: MyJwkEcKey = serde_json::from_str(request)
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
            .to_jwk_ec_key(true)
            .and_then(|jwk| {
                jwk.to_public_key::<p521::NistP521>()
                    .map_err(|source| Error::key_cause("invalid public point", source))
            })
            .map_err(|source| Error::request_cause("invalid public key", source))?;
        let response =
            diffie_hellman_public_key(&secret.to_nonzero_scalar(), request_key.as_affine())?;
        serialize_string(&response, "recovery response")
    }
}

/// Generate private signing and recovery JWKs without writing files.
/// OS entropy and serialization failures are returned to the caller.
pub fn create_new_key_set() -> Result<Vec<String>> {
    create_new_key_set_with_rng(&mut OsRng)
}

fn create_new_key_set_with_rng(entropy: &mut impl CryptoRngCore) -> Result<Vec<String>> {
    let mut rng = crypto_rng(entropy, RandomPurpose::KeyGeneration)?;
    Ok(vec![
        create_new_jwk("ES512", &["sign", "verify"], &mut rng)?,
        create_new_jwk("ECMR", &["deriveKey"], &mut rng)?,
    ])
}

// P-521 0.13 uses infallible fill_bytes internally, even in try_sign. Seed a
// CSPRNG through a fallible call before entering those APIs. ChaCha20's fills
// cannot fail and every operation receives a fresh OS seed.
fn crypto_rng(entropy: &mut impl CryptoRngCore, operation: RandomPurpose) -> Result<ChaCha20Rng> {
    ChaCha20Rng::from_rng(entropy).map_err(|source| Error::Randomness {
        operation,
        source: Box::new(source),
    })
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

fn create_key_file(path: &Path) -> io::Result<File> {
    let file = File::options().write(true).create_new(true).open(path)?;
    set_file_permissions(&file)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn set_file_permissions(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o440); // Read access for owner and group.
    file.set_permissions(perms)
}

#[cfg(not(target_os = "linux"))]
fn set_file_permissions(_file: &File) -> io::Result<()> {
    Ok(())
}

fn load_keys_from_dir(db_path: &Path) -> Result<HashMap<String, StoredKey>> {
    let mut loaded = HashMap::new();
    let entries = db_path.read_dir().map_err(|source| Error::KeyDirectory {
        path: db_path.into(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| Error::KeyDirectory {
                path: db_path.into(),
                source,
            })?
            .path();
        if path.extension() == Some(std::ffi::OsStr::new("jwk")) {
            let json = std::fs::read_to_string(&path).map_err(|source| Error::KeyRead {
                path: path.clone(),
                source,
            })?;
            load_stored_key(&mut loaded, &json, KeyLocation::File(path))?;
        }
    }
    Ok(loaded)
}

fn load_keys_from_vec<T: AsRef<str>>(keys: &[T]) -> Result<HashMap<String, StoredKey>> {
    let mut loaded = HashMap::new();
    for (index, json) in keys.iter().enumerate() {
        load_stored_key(&mut loaded, json.as_ref(), KeyLocation::Input(index))?;
    }
    Ok(loaded)
}

fn load_stored_key(
    loaded: &mut HashMap<String, StoredKey>,
    json: &str,
    location: KeyLocation,
) -> Result<()> {
    let load = || -> Result<(String, StoredKey)> {
        let jwk = parse_stored_key(json)?;
        let kid = jwk.thumbprint()?;
        let key = validate_stored_key(jwk, &kid)?;
        Ok((kid, key))
    };
    let (kid, key) = load().map_err(|source| Error::InvalidStoredKey {
        location,
        source: Box::new(source),
    })?;
    loaded.insert(kid, key);
    Ok(())
}

fn parse_stored_key(json: &str) -> Result<MyJwkEcKey> {
    serde_json::from_str(json).map_err(|source| Error::key_cause("invalid JSON", JsonError(source)))
}

fn validate_stored_key(jwk: MyJwkEcKey, kid: &str) -> Result<StoredKey> {
    match jwk.alg.as_deref() {
        Some("ES512") => {
            require_operation(&jwk, kid, Algorithm::Es512, KeyOperation::Sign)?;
            require_operation(&jwk, kid, Algorithm::Es512, KeyOperation::Verify)?;
        }
        Some("ECMR") => require_operation(&jwk, kid, Algorithm::Ecmr, KeyOperation::DeriveKey)?,
        _ => return Err(Error::invalid_key("algorithm must be ES512 or ECMR")),
    }
    let secret = jwk
        .to_jwk_ec_key(false)?
        .to_secret_key::<p521::NistP521>()
        .map_err(|source| Error::key_cause("invalid private key", source))?;
    let material = if jwk.alg.as_deref() == Some("ES512") {
        // P-521 0.13 wraps the generic ECDSA key; construct it without a
        // serialized scalar copy or fallible reparsing.
        KeyMaterial::Signing(::ecdsa::SigningKey::<p521::NistP521>::from(&secret).into())
    } else {
        KeyMaterial::Recovery(secret)
    };
    let mut public = jwk.to_public_key();
    if let Some(ops) = &mut public.key_ops {
        ops.retain(|op| op != "sign");
    }
    Ok(StoredKey { public, material })
}

fn create_new_jwk(alg: &str, key_ops: &[&str], rng: &mut ChaCha20Rng) -> Result<String> {
    let secret = p521::SecretKey::random(rng);
    let mut jwk = format_public_key(&secret.public_key())?;
    jwk.d = Some(Base64UrlUnpadded::encode_string(&secret.to_bytes()));
    jwk.alg = Some(alg.into());
    jwk.key_ops = Some(key_ops.iter().map(|op| (*op).into()).collect());
    serialize_string(&jwk, "generated private key")
}

fn format_public_key(public: &p521::PublicKey) -> Result<MyJwkEcKey> {
    let point = public.to_encoded_point(false);
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

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
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

impl MyJwkEcKey {
    /// Convert and validate a P-521 JWK. Private conversion requires a scalar
    /// whose public point matches the supplied coordinates.
    pub fn to_jwk_ec_key(&self, public: bool) -> Result<JwkEcKey> {
        if self.kty != "EC" {
            return Err(Error::invalid_key("key type must be EC"));
        }
        if self.crv != "P-521" {
            return Err(Error::invalid_key("curve must be P-521"));
        }
        if !public && self.d.is_none() {
            return Err(Error::invalid_key("private scalar is missing"));
        }
        #[derive(Serialize)]
        struct Fields<'a> {
            crv: &'a str,
            kty: &'a str,
            x: &'a str,
            y: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            d: Option<&'a str>,
        }
        let fields = Fields {
            crv: &self.crv,
            kty: &self.kty,
            x: &self.x,
            y: &self.y,
            d: if public { None } else { self.d.as_deref() },
        };
        let json = serialize_string(&fields, "EC key")?;
        let jwk = JwkEcKey::from_str(&json)
            .map_err(|source| Error::key_cause("invalid EC key", source))?;
        if public {
            jwk.to_public_key::<p521::NistP521>()
                .map_err(|source| Error::key_cause("invalid public point", source))?;
        } else {
            jwk.to_secret_key::<p521::NistP521>().map_err(|source| {
                Error::key_cause("invalid private scalar or mismatched public point", source)
            })?;
        }
        Ok(jwk)
    }

    pub fn to_public_key(&self) -> MyJwkEcKey {
        let mut ret = self.clone();
        ret.d = None;
        ret
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
    use elliptic_curve::rand_core::{CryptoRng, RngCore};
    use std::error::Error as _;

    struct FailingEntropy;

    impl CryptoRng for FailingEntropy {}

    impl RngCore for FailingEntropy {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible entropy API called")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("infallible entropy API called")
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            panic!("infallible entropy API called")
        }

        fn try_fill_bytes(
            &mut self,
            _dest: &mut [u8],
        ) -> std::result::Result<(), elliptic_curve::rand_core::Error> {
            Err(elliptic_curve::rand_core::Error::new(io::Error::other(
                "injected entropy failure",
            )))
        }
    }

    /// Assures: KEY-GEN-001
    #[test]
    fn entropy_failures_return_errors_before_key_generation_or_signing() {
        let error = create_new_key_set_with_rng(&mut FailingEntropy).unwrap_err();
        assert!(matches!(
            error,
            Error::Randomness {
                operation: RandomPurpose::KeyGeneration,
                ..
            }
        ));
        assert!(error
            .source()
            .unwrap()
            .is::<elliptic_curve::rand_core::Error>());
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
                .adv_with_rng(selection.as_deref(), &mut FailingEntropy)
                .unwrap_err();
            assert!(matches!(
                error,
                Error::Randomness {
                    operation: RandomPurpose::AdvertisementSigning,
                    ..
                }
            ));
            assert!(error
                .source()
                .unwrap()
                .is::<elliptic_curve::rand_core::Error>());
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

    struct FailingWriter {
        file: File,
        written: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.written {
                return Err(io::Error::other("injected write failure"));
            }
            self.written = true;
            self.file.write(&bytes[..bytes.len().min(8)])
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Assures: KEY-STORE-001, ERR-DIAG-001
    #[test]
    fn initialization_propagates_create_and_partial_write_failures() {
        for fail_on in [1, 2] {
            for fail_create in [true, false] {
                let dir = tempfile::tempdir().unwrap();
                let mut opened = 0;
                let result = TangyLib::init_with_key_writer(
                    KeySource::LocalDir(dir.path()),
                    |path| -> io::Result<Box<dyn Write>> {
                        opened += 1;
                        if opened != fail_on {
                            return Ok(Box::new(create_key_file(path)?));
                        }
                        if fail_create {
                            Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "injected create failure",
                            ))
                        } else {
                            Ok(Box::new(FailingWriter {
                                file: create_key_file(path)?,
                                written: false,
                            }))
                        }
                    },
                );
                let error = result.unwrap_err();
                assert_eq!(opened, fail_on);
                assert_eq!(
                    match &error {
                        Error::KeyWrite {
                            path,
                            operation,
                            source,
                        } => {
                            assert_eq!(path.parent(), Some(dir.path()));
                            assert_eq!(
                                *operation,
                                if fail_create {
                                    WriteStep::Create
                                } else {
                                    WriteStep::Write
                                }
                            );
                            source.kind()
                        }
                        _ => panic!("unexpected error: {error:?}"),
                    },
                    if fail_create {
                        io::ErrorKind::PermissionDenied
                    } else {
                        io::ErrorKind::Other
                    }
                );
                let snapshot = || {
                    std::fs::read_dir(dir.path())
                        .unwrap()
                        .map(|entry| {
                            let path = entry.unwrap().path();
                            let bytes = std::fs::read(&path).unwrap();
                            (path, bytes)
                        })
                        .collect::<std::collections::BTreeMap<_, _>>()
                };
                let before = snapshot();
                assert_eq!(
                    before.len(),
                    if fail_create { fail_on - 1 } else { fail_on }
                );
                if !before.is_empty() {
                    assert!(TangyLib::init(KeySource::LocalDir(dir.path())).is_err());
                    assert_eq!(before, snapshot());
                }
            }
        }
    }

    /// Assures: KEY-STORE-001
    #[test]
    fn key_creation_does_not_overwrite_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.jwk");
        std::fs::write(&path, "existing key").unwrap();
        assert_eq!(
            create_key_file(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "existing key");
    }
}
