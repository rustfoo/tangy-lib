// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build Tang advertisements and recovery responses from a validated server key set.
//!
//! [`TangyLib`] connects key storage and cryptographic key conversion to the two
//! Tang protocol operations: advertising public keys and helping clients recover
//! secrets. Callers supply key identifiers and request bodies, then send the
//! returned JavaScript Object Notation (JSON) strings through their transport.
//!
//! [`TangyLib::init`] delegates loading and validation to the key-store module.
//! Construction requires at least one active signing key and one active recovery
//! key, retains their typed private material, and builds the default advertisement.
//! An instance holds this key-set snapshot; loading a subsequent rotation requires
//! initializing a new instance.
//!
//! [`TangyLib::adv`] advertises the active public keys as a JSON Web Key (JWK) set
//! inside a JSON Web Signature (JWS). Every active signing key signs the payload
//! using P-521 with SHA-512 (`ES512`). A single signature uses the flattened JWS
//! representation; multiple signatures use the general representation with a
//! `signatures` array. The protected header, payload and signatures use URL-safe
//! Base64 without padding. Private scalars are omitted from the advertised keys.
//!
//! `adv(None)` returns the advertisement cached during initialization and needs
//! no fresh randomness. `adv(Some(kid))` requires a signing-key thumbprint and
//! constructs a fresh advertisement signed by all active signers. Selecting a
//! rotated signer adds its signature over the same active payload, allowing a
//! client holding its old public key to verify the current set. Rotated keys
//! remain absent from the payload, and selecting an active signer includes its
//! signature once. Fresh signing obtains randomness through the shared fallible
//! seeding helper.
//!
//! [`TangyLib::rec`] performs elliptic-curve message recovery (`ECMR`). Its `kid`
//! selects an active or rotated server recovery key by thumbprint; its request
//! body supplies a P-521 public point as a JWK. The JWK module validates the
//! coordinates. Optional `alg` and `key_ops` fields must, when supplied, specify
//! `ECMR` and permit `deriveKey`. Recovery multiplies the client's point by the
//! server's private scalar and returns the full resulting public point as a JWK
//! with those algorithm and operation fields. This full-point response preserves
//! Tang compatibility and keeps rotated recovery keys usable by existing clients.
//!
//! Unknown identifiers return [`Error::KeyNotFound`], selecting a server key with
//! the wrong role returns [`Error::ForbiddenOperation`], and malformed or invalid
//! recovery input returns [`Error::InvalidRequest`]. Signing, randomness and
//! serialization failures retain their operation context through typed errors.

use base64ct::{Base64UrlUnpadded, Encoding};
use p521::{
    ecdsa::{self, signature::RandomizedSigner},
    elliptic_curve,
};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::{
    jwk::{format_public_key, parse_private_jwk},
    key_store::{self, KeyMaterial, StoredKey},
    support::{crypto_rng, serialize, serialize_string},
    Algorithm, Error, JsonError, KeyOperation, KeySource, MyJwkEcKey, RandomPurpose, Result,
};

/// A validated active/rotated key set serving Tang protocol JSON responses.
/// Private key material is redacted from debug output.
#[derive(Debug)]
pub struct TangyLib {
    keys: BTreeMap<String, StoredKey>,
    default_adv: String,
}

impl TangyLib {
    /// Load and validate private keys, generating only for an empty directory.
    /// Invalid, duplicate or incomplete existing stores return typed errors.
    pub fn init(source: KeySource) -> Result<Self> {
        key_store::initialize(source)
    }

    pub(crate) fn from_keys(keys: BTreeMap<String, StoredKey>) -> Result<Self> {
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
        tangy.default_adv = tangy.build_advertisement(None)?;
        Ok(tangy)
    }

    /// Return a signed advertisement of active public keys.
    /// `None` serves the cached advertisement signed by all active signers.
    /// Selecting a rotated signing thumbprint adds its signature to the active set.
    pub fn adv(&self, skid: Option<&str>) -> Result<String> {
        match skid {
            None => Ok(self.default_adv.clone()),
            Some(_) => self.build_advertisement(skid),
        }
    }

    fn build_advertisement(&self, skid: Option<&str>) -> Result<String> {
        self.adv_with_rng(skid, &mut getrandom::fill)
    }

    pub(crate) fn adv_with_rng<E: std::error::Error + Send + Sync + 'static>(
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

    /// Recover a client P-521 point using an active or rotated ECMR key.
    /// `kid` is the server key thumbprint; `request` is a public JWK JSON string.
    /// Invalid client material returns [`Error::InvalidRequest`].
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
