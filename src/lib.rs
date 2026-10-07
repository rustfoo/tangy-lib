use std::{
    collections::HashMap,
    fs::File,
    io::{self, Write},
    path::Path,
    str::FromStr,
};

use base64ct::Encoding;
use ecdsa::SigningKey;
use elliptic_curve::{rand_core::OsRng, JwkEcKey};
use p521::ecdsa;
use serde::Serialize;
use sha2::Digest;

#[derive(Debug)]
pub struct TangyLib {
    keys: std::collections::HashMap<String, MyJwkEcKey>,
    signing_keys: Vec<MyJwkEcKey>,
    default_adv: String,
}

#[derive(PartialEq)]
pub enum KeySource<'a> {
    LocalDir(&'a Path),
    Vector(&'a Vec<&'a str>),
}

impl TangyLib {
    pub fn init(source: KeySource) -> Result<Self, std::io::Error> {
        Self::init_with_key_writer(source, create_key_file)
    }

    // Keep the file-opening boundary injectable so write failures can be tested
    // on every platform, including when tests run with elevated privileges.
    fn init_with_key_writer<W: Write>(
        source: KeySource,
        mut create: impl FnMut(&Path) -> io::Result<W>,
    ) -> io::Result<Self> {
        let mut loaded_keys = match source {
            KeySource::LocalDir(dir) => load_keys_from_dir(dir)?,
            KeySource::Vector(keys) => load_keys_from_vec(keys)?,
        };

        let ecmr_exists = loaded_keys
            .values()
            .any(|v| v.alg.as_deref() == Some("ECMR"));
        let es512_exists = loaded_keys
            .values()
            .any(|v| v.alg.as_deref() == Some("ES512"));

        if (!ecmr_exists && es512_exists) || (ecmr_exists && !es512_exists) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Key loading file error",
            ));
        }

        if !ecmr_exists && !es512_exists {
            match source {
                KeySource::LocalDir(dir) => {
                    let keys = create_new_key_set();
                    for k in keys.iter() {
                        let jwk: MyJwkEcKey = serde_json::from_str(k).map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Unable to create new JWK: {e}"),
                            )
                        })?;
                        let thumbprint = jwk.thumbprint();
                        let path = dir.join(format!("{}.jwk", thumbprint));
                        let mut file = create(&path)?;
                        file.write_all(k.as_bytes())?;
                        loaded_keys.insert(thumbprint, jwk);
                    }
                }
                KeySource::Vector(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "ES512 and ECMR keys not present in input vector",
                    ));
                }
            }
        }

        let signing_keys: Vec<MyJwkEcKey> = loaded_keys
            .values()
            .filter(|key| key.alg.as_deref() == Some("ES512"))
            .cloned()
            .collect();

        if signing_keys.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Signing key not found",
            ));
        }

        let mut tangy = Self {
            keys: loaded_keys,
            signing_keys,
            default_adv: "".into(),
        };

        tangy.default_adv = tangy.adv_internal(None)?;

        Ok(tangy)
    }

    pub fn adv(&self, skid: Option<&str>) -> Result<String, std::io::Error> {
        if skid.is_none() {
            return Ok(self.default_adv.to_owned());
        }
        self.adv_internal(skid)
    }

    pub fn adv_internal(&self, skid: Option<&str>) -> Result<String, std::io::Error> {
        #[derive(serde::Serialize)]
        struct Signature {
            protected: String,
            signature: String,
        }
        #[derive(serde::Serialize)]
        struct Advertise {
            payload: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            protected: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            signature: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            signatures: Option<Vec<Signature>>,
        }

        #[derive(serde::Serialize)]
        struct Payload {
            keys: Vec<MyJwkEcKey>,
        }

        let keys: Vec<&MyJwkEcKey> = self.keys.values().collect();

        if let Some(kid) = skid {
            let key = self.keys.get(kid).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Requested signing key {} not found", kid),
                )
            })?;
            require_operation(key, "ES512", "sign")?;
        }
        // Like Tang, retain signatures for all advertised verification keys.
        // Clevis verifies all of them even when a particular key was requested.
        let signing_keys = &self.signing_keys;

        let payload = base64ct::Base64UrlUnpadded::encode_string(
            serde_json::to_string(&Payload {
                keys: keys
                    .iter()
                    .map(|v| {
                        let mut k = v.to_public_key();
                        let mut ops = k.key_ops.take();
                        if let Some(ops) = &mut ops {
                            ops.retain(|v| *v != "sign");
                        }
                        k.key_ops = ops;
                        k
                    })
                    .collect(),
            })
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unable to encode adv message: {e}"),
                )
            })?
            .as_bytes(),
        );

        // As per tang reference implementation
        let protected = base64ct::Base64UrlUnpadded::encode_string(
            r#"{"alg":"ES512","cty":"jwk-set+json"}"#.as_bytes(),
        );

        let signing_keys: Vec<SigningKey> = signing_keys
            .iter()
            .map(|k| {
                require_operation(k, "ES512", "sign")?;
                let secret = k
                    .try_to_jwk_ec_key(false)?
                    .to_secret_key::<p521::NistP521>()
                    .map_err(|_| invalid_data("Invalid signing key"))?;
                SigningKey::from_bytes(&secret.to_bytes())
                    .map_err(|_| invalid_data("Invalid signing key"))
            })
            .collect::<io::Result<_>>()?;

        // The protected and payload fields are signed, as base64url encoded string
        // joined with a period.
        let to_sign = format!("{}.{}", &protected, &payload);

        let signatures: Vec<ecdsa::Signature> = signing_keys
            .iter()
            .map(|k| {
                ecdsa::signature::Signer::try_sign(k, to_sign.as_bytes())
                    .map_err(|_| io::Error::other("Advertisement signing failed"))
            })
            .collect::<io::Result<_>>()?;

        if signatures.len() == 1 {
            serde_json::to_string(&Advertise {
                payload,
                protected: Some(protected),
                signature: Some(base64ct::Base64UrlUnpadded::encode_string(
                    &signatures[0].to_bytes(),
                )),
                signatures: None,
            })
            .map_err(|_| invalid_data("Unable to encode advertisement"))
        } else {
            serde_json::to_string(&Advertise {
                payload,
                protected: None,
                signature: None,
                signatures: Some(
                    signatures
                        .iter()
                        .map(|s| Signature {
                            protected: protected.to_owned(),
                            signature: base64ct::Base64UrlUnpadded::encode_string(&s.to_bytes()),
                        })
                        .collect(),
                ),
            })
            .map_err(|_| invalid_data("Unable to encode advertisement"))
        }
    }

    pub fn rec(&self, kid: &str, request: &str) -> Result<String, std::io::Error> {
        let key = self.keys.get(kid).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Requested key not found")
        })?;
        require_operation(key, "ECMR", "deriveKey")?;

        let request_key: MyJwkEcKey = serde_json::from_str(request)
            .map_err(|_| invalid_data("Invalid recovery request JSON"))?;
        // Tang permits omitted request metadata, but rejects explicit conflicts.
        if request_key.alg.as_deref().is_some_and(|alg| alg != "ECMR") {
            return Err(invalid_data("Recovery request must use ECMR"));
        }
        if request_key
            .key_ops
            .as_ref()
            .is_some_and(|ops| !ops.iter().any(|op| op == "deriveKey"))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Recovery request does not permit derivation",
            ));
        }
        let request_key = request_key
            .try_to_jwk_ec_key(true)?
            .to_public_key::<p521::NistP521>()
            .map_err(|_| invalid_data("Invalid recovery request point"))?;
        let secret = key
            .try_to_jwk_ec_key(false)?
            .to_secret_key::<p521::NistP521>()
            .map_err(|_| invalid_data("Invalid recovery key"))?;

        let p = diffie_hellman_public_key(&secret.to_nonzero_scalar(), request_key.as_affine())?;

        serde_json::to_string(&p).map_err(|_| invalid_data("Unable to encode recovery response"))
    }
}

pub fn create_new_key_set() -> Vec<String> {
    let es512_jwk = create_new_jwk("ES512", &["sign", "verify"]);
    let ecmr_jwk = create_new_jwk("ECMR", &["deriveKey"]);
    vec![es512_jwk, ecmr_jwk]
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require_operation(key: &MyJwkEcKey, algorithm: &str, operation: &str) -> io::Result<()> {
    if key.alg.as_deref() != Some(algorithm)
        || !key
            .key_ops
            .as_ref()
            .is_some_and(|ops| ops.iter().any(|op| op == operation))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Key does not permit the requested operation",
        ));
    }
    Ok(())
}

fn create_key_file(path: &Path) -> io::Result<File> {
    let file = File::options().write(true).create_new(true).open(path)?;
    set_file_permissions(&file)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn set_file_permissions(file: &File) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o440); // Read access for owner and group.
    file.set_permissions(perms)
}

#[cfg(not(target_os = "linux"))]
fn set_file_permissions(_file: &File) -> Result<(), std::io::Error> {
    Ok(())
}

fn load_keys_from_dir(db_path: &Path) -> Result<HashMap<String, MyJwkEcKey>, std::io::Error> {
    if !db_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Key database \"{}\" does not exist",
                db_path.to_string_lossy()
            ),
        ));
    }

    if !db_path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "Key database \"{}\" is not a directory",
                db_path.to_string_lossy()
            ),
        ));
    }

    let mut keys = Vec::new();
    for entry in db_path.read_dir()? {
        let path = entry?.path();
        if path.extension() == Some(std::ffi::OsStr::new("jwk")) {
            keys.push(std::fs::read_to_string(&path)?);
        }
    }

    load_keys_from_vec(&keys)
}

fn load_keys_from_vec<T: AsRef<str>>(
    keys: &[T],
) -> Result<HashMap<String, MyJwkEcKey>, std::io::Error> {
    let mut loaded = HashMap::new();
    for key in keys {
        let jwk: MyJwkEcKey = serde_json::from_str(key.as_ref())
            .map_err(|_| invalid_data("Invalid stored key JSON"))?;
        match jwk.alg.as_deref() {
            Some("ES512") => {
                require_operation(&jwk, "ES512", "sign")?;
                require_operation(&jwk, "ES512", "verify")?;
            }
            Some("ECMR") => require_operation(&jwk, "ECMR", "deriveKey")?,
            _ => return Err(invalid_data("Unsupported stored key algorithm")),
        }
        jwk.try_to_jwk_ec_key(false)?
            .to_secret_key::<p521::NistP521>()
            .map_err(|_| invalid_data("Invalid stored private key"))?;
        loaded.insert(jwk.thumbprint(), jwk);
    }
    Ok(loaded)
}

// For future directory monitoring
//fn scan_folder(dir: &Path) -> String {
//    let mut sha256 = sha2::Sha256::new();
//    dir.read_dir()
//        .unwrap()
//        .filter_map(|f| f.ok())
//        .map(|e| e.path())
//        .filter(|f| f.extension() == Some(std::ffi::OsStr::new("jwk")))
//        .for_each(|filename| {
//            let mut file = std::fs::File::open(&filename).unwrap();
//            let filesize = filesize::file_real_size(&filename).unwrap_or(1024 * 10);
//            if filesize < 1024 * 10 {
//                let mut content = String::new();
//                file.read_to_string(&mut content).unwrap();
//                sha256.update(content.as_bytes());
//            }
//        });
//
//    base64ct::Base64UrlUnpadded::encode_string(&sha256.finalize())
//}

fn create_new_jwk(alg: &str, key_ops: &[&str]) -> String {
    let priv_key = elliptic_curve::SecretKey::<p521::NistP521>::random(&mut OsRng);
    let jwk = priv_key.to_jwk();
    let encoded_point = jwk.to_encoded_point::<p521::NistP521>().unwrap();
    let mut buf = [0; 1000];

    let x = base64ct::Base64Url::encode(encoded_point.x().unwrap(), &mut buf)
        .unwrap()
        .to_string();

    let y = base64ct::Base64Url::encode(encoded_point.y().unwrap(), &mut buf)
        .unwrap()
        .to_string();

    serde_json::to_string(&MyJwkEcKey {
        alg: Some(alg.into()),
        kty: "EC".into(),
        crv: jwk.crv().into(),
        x: x.to_owned(),
        y: y.to_owned(),
        d: Some(
            base64ct::Base64Url::encode(priv_key.to_bytes().as_slice(), &mut buf)
                .unwrap()
                .to_string(),
        ),
        key_ops: Some(key_ops.iter().map(|k| k.to_string()).collect()),
        use_: None,
        kid: None,
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    })
    .unwrap()
}

fn diffie_hellman_public_key(
    secret_key: &elliptic_curve::NonZeroScalar<p521::NistP521>,
    public_key: &elliptic_curve::AffinePoint<p521::NistP521>,
) -> io::Result<MyJwkEcKey> {
    let public_point = elliptic_curve::ProjectivePoint::<p521::NistP521>::from(*public_key);
    let secret_point = (public_point * secret_key.as_ref()).to_affine();
    let generated_public_key = p521::PublicKey::from_affine(secret_point)
        .map_err(|_| invalid_data("Invalid recovery result point"))?;

    let mut formatted_public_key: MyJwkEcKey =
        serde_json::from_str(generated_public_key.to_jwk_string().as_str())
            .map_err(|_| invalid_data("Unable to encode recovery result point"))?;

    formatted_public_key.alg = Some("ECMR".into());
    formatted_public_key.crv = "P-521".into();
    formatted_public_key.kty = "EC".into();
    formatted_public_key.key_ops = Some(vec!["deriveKey".into()]);

    Ok(formatted_public_key)
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
    pub fn to_jwk_ec_key(&self, public: bool) -> JwkEcKey {
        self.try_to_jwk_ec_key(public).unwrap()
    }

    fn try_to_jwk_ec_key(&self, public: bool) -> io::Result<JwkEcKey> {
        if self.kty != "EC" {
            return Err(invalid_data("Only EC keys are supported"));
        }
        let mut content: HashMap<String, String> = HashMap::new();
        content.insert("crv".into(), self.crv.to_owned());
        content.insert("kty".into(), self.kty.to_owned());
        content.insert("x".into(), self.x.to_owned());
        content.insert("y".into(), self.y.to_owned());
        if !public {
            if let Some(d) = &self.d {
                content.insert("d".into(), d.to_owned());
            }
        }
        let json =
            serde_json::to_string(&content).map_err(|_| invalid_data("Unable to encode EC key"))?;
        JwkEcKey::from_str(&json).map_err(|_| invalid_data("Invalid EC key"))
    }

    pub fn to_public_key(&self) -> MyJwkEcKey {
        let mut ret = self.clone();
        ret.d = None;
        ret
    }

    pub fn thumbprint(&self) -> String {
        // For EC type the following fields are required to be
        // present and in lexicographic order
        #[derive(Serialize)]
        struct Required {
            crv: String,
            kty: String,
            x: String,
            y: String,
        }

        let required_fields = Required {
            crv: self.crv.to_owned(),
            kty: self.kty.to_owned(),
            x: self.x.to_owned(),
            y: self.y.to_owned(),
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(serde_json::to_string(&required_fields).unwrap().as_bytes());
        base64ct::Base64UrlUnpadded::encode_string(&hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    error.kind(),
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
