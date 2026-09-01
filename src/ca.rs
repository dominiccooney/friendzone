use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

const CERT_FILE: &str = "friendzone-ca.pem";
const KEY_FILE: &str = "friendzone-ca-key.pem";

pub struct AuthorityFiles {
    pub cert_pem: String,
    pub key_pem: String,
}

impl AuthorityFiles {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("create data directory {}", data_dir.display()))?;
        let cert_path = data_dir.join(CERT_FILE);
        let key_path = data_dir.join(KEY_FILE);

        if cert_path.exists() != key_path.exists() {
            anyhow::bail!("CA certificate and key must either both exist or both be absent");
        }

        if cert_path.exists() {
            return Ok(Self {
                cert_pem: fs::read_to_string(&cert_path)
                    .with_context(|| format!("read {}", cert_path.display()))?,
                key_pem: fs::read_to_string(&key_path)
                    .with_context(|| format!("read {}", key_path.display()))?,
            });
        }

        let key = KeyPair::generate().context("generate CA key")?;
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Friendzone Local CA");
        name.push(DnType::OrganizationName, "Friendzone");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).context("create CA certificate")?;
        let files = Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        };
        write_private(&key_path, files.key_pem.as_bytes())?;
        fs::write(&cert_path, files.cert_pem.as_bytes())
            .with_context(|| format!("write {}", cert_path.display()))?;
        Ok(files)
    }

    pub fn issuer(&self) -> Result<Issuer<'static, KeyPair>> {
        let key = KeyPair::from_pem(&self.key_pem).context("parse CA key")?;
        Issuer::from_ca_cert_pem(&self.cert_pem, key).context("parse CA certificate")
    }
}

#[cfg(unix)]
fn write_private(path: &Path, value: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(value).context("write CA key")
}

#[cfg(not(unix))]
fn write_private(path: &Path, value: &[u8]) -> Result<()> {
    fs::write(path, value).with_context(|| format!("write {}", path.display()))
}

pub fn default_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("friendzone")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_persists() {
        let dir = std::env::temp_dir().join(format!("fz-ca-{}", uuid::Uuid::new_v4()));
        let first = AuthorityFiles::load_or_create(&dir).unwrap();
        let second = AuthorityFiles::load_or_create(&dir).unwrap();
        assert_eq!(first.cert_pem, second.cert_pem);
        assert!(first.issuer().is_ok());
        fs::remove_dir_all(dir).unwrap();
    }
}
