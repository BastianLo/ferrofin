//! The LDAP wire side of the provider: connect (plain, `ldaps://` or StartTLS),
//! bind, search with referral following, and password changes.
//!
//! Port of `ConnectToLdap`, `GetConnectionOptions`, `GetSearchConstraints` (+
//! `LdapAuthHandler`) and the `ChangePassword` operations of
//! `LdapAuthenticationProviderPlugin`, over the pure-Rust `ldap3` client instead
//! of `Novell.Directory.Ldap`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ferrofin_model::ldap::LdapConfiguration;
use ldap3::exop::PasswordModify;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError, Mod, Scope, SearchEntry};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// The OID of the Password Modify extended operation (RFC 3062).
const PASSWORD_MODIFY_OID: &str = "1.3.6.1.4.1.4203.1.11.1";

/// How long a TCP connect may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long one LDAP operation may take, so a stalled directory cannot hold a
/// login (and the user's login lock) forever.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// How many referrals deep a search follows (Novell's default hop limit).
const MAX_REFERRAL_HOPS: u8 = 10;

/// One entry of a search result, attribute names compared without case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// The entry's DN.
    pub dn: String,
    /// Text attribute values.
    pub attrs: HashMap<String, Vec<String>>,
    /// Attribute values that are not UTF-8.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

/// One attribute's first value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
    /// A UTF-8 value.
    Text(String),
    /// A value that is not UTF-8.
    Binary(Vec<u8>),
}

impl Entry {
    fn from_search_entry(entry: SearchEntry) -> Self {
        Self {
            dn: entry.dn,
            attrs: entry.attrs,
            bin_attrs: entry.bin_attrs,
        }
    }

    /// The first value of attribute `name` (LDAP attribute names are case-insensitive).
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<AttributeValue> {
        if let Some(text) = self
            .attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.first())
        {
            return Some(AttributeValue::Text(text.clone()));
        }
        self.bin_attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.first())
            .map(|bytes| AttributeValue::Binary(bytes.clone()))
    }

    /// The first text value of attribute `name`.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<String> {
        match self.attribute(name)? {
            AttributeValue::Text(text) => Some(text),
            AttributeValue::Binary(_) => None,
        }
    }
}

/// An open, driven connection.
pub struct Connection {
    ldap: Ldap,
    /// Whether the last bind authenticated (Novell's `Bound`): `false` after an
    /// anonymous bind.
    pub bound: bool,
}

/// What failed while talking to the directory.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The TLS settings could not be built (a CA, certificate or key file).
    #[error("{0}")]
    Tls(String),
    /// The directory or the connection failed.
    #[error(transparent)]
    Ldap(#[from] LdapError),
    /// The server cannot change passwords the way the configuration says.
    #[error("{0}")]
    Unsupported(String),
}

impl ClientError {
    /// Whether the error is a malformed filter (the `TestLdapFilters` `400`).
    #[must_use]
    pub fn is_filter_error(&self) -> bool {
        matches!(self, Self::Ldap(LdapError::FilterParsing))
    }
}

/// The server URL for the configured host and port.
fn server_url(config: &LdapConfiguration) -> String {
    let scheme = if config.use_ssl { "ldaps" } else { "ldap" };
    let host = &config.ldap_server;
    if host.contains(':') && !host.starts_with('[') {
        format!("{scheme}://[{host}]:{}", config.ldap_port)
    } else {
        format!("{scheme}://{host}:{}", config.ldap_port)
    }
}

/// The connection settings for `config` (port of `GetConnectionOptions`).
fn settings(config: &LdapConfiguration) -> Result<LdapConnSettings, ClientError> {
    let mut settings = LdapConnSettings::new()
        .set_conn_timeout(CONNECT_TIMEOUT)
        .set_starttls(config.use_start_tls && !config.use_ssl);
    if let Some(tls) = tls_config(config)? {
        settings = settings.set_config(tls);
    } else if config.skip_ssl_verify {
        settings = settings.set_no_tls_verify(true);
    }
    Ok(settings)
}

/// A rustls configuration when the defaults do not do (a custom CA or a client
/// certificate); `None` keeps `ldap3`'s, the platform roots.
fn tls_config(config: &LdapConfiguration) -> Result<Option<Arc<ClientConfig>>, ClientError> {
    let client_cert =
        !config.ldap_client_cert_path.is_empty() && !config.ldap_client_key_path.is_empty();
    let custom_ca = !config.ldap_root_ca_path.is_empty();
    // Only a client certificate, or a CA that SkipSslVerify does not override,
    // needs a configuration of our own.
    let custom_roots = custom_ca && !config.skip_ssl_verify;
    if !(client_cert || custom_roots) {
        return Ok(None);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Tls(format!("TLS setup failed: {e}")))?;
    // Upstream checks SkipSslVerify before the custom CA.
    let builder = if config.skip_ssl_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
    } else {
        let mut roots = RootCertStore::empty();
        if custom_ca {
            for cert in CertificateDer::pem_file_iter(&config.ldap_root_ca_path).map_err(|e| {
                ClientError::Tls(format!(
                    "reading LDAP root CA {}: {e}",
                    config.ldap_root_ca_path
                ))
            })? {
                let cert = cert.map_err(|e| {
                    ClientError::Tls(format!(
                        "reading LDAP root CA {}: {e}",
                        config.ldap_root_ca_path
                    ))
                })?;
                roots
                    .add(cert)
                    .map_err(|e| ClientError::Tls(format!("LDAP root CA: {e}")))?;
            }
        } else {
            let native = rustls_native_certs::load_native_certs();
            for error in &native.errors {
                tracing::warn!(error = %error, "loading a system root certificate for LDAP");
            }
            roots.add_parsable_certificates(native.certs);
        }
        builder.with_root_certificates(roots)
    };
    let tls = if client_cert {
        let certs = CertificateDer::pem_file_iter(&config.ldap_client_cert_path)
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .map_err(|e| {
                ClientError::Tls(format!(
                    "reading LDAP client certificate {}: {e}",
                    config.ldap_client_cert_path
                ))
            })?;
        let key = PrivateKeyDer::from_pem_file(&config.ldap_client_key_path).map_err(|e| {
            ClientError::Tls(format!(
                "reading LDAP client key {}: {e}",
                config.ldap_client_key_path
            ))
        })?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| ClientError::Tls(format!("LDAP client certificate: {e}")))?
    } else {
        builder.with_no_client_auth()
    };
    Ok(Some(Arc::new(tls)))
}

/// `SkipSslVerify`: any server certificate is accepted (the handshake
/// signatures are still checked, so the session keys belong to the presenter).
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl Connection {
    /// Connects to the configured server (and runs StartTLS when configured),
    /// without binding.
    ///
    /// # Errors
    /// [`ClientError`] when the TLS settings or the connection fail.
    pub async fn open(config: &LdapConfiguration) -> Result<Self, ClientError> {
        Self::open_url(config, &server_url(config)).await
    }

    async fn open_url(config: &LdapConfiguration, url: &str) -> Result<Self, ClientError> {
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings(config)?, url).await?;
        tokio::spawn(async move {
            if let Err(error) = conn.drive().await {
                tracing::debug!(error = %error, "LDAP connection closed");
            }
        });
        ldap.with_timeout(OPERATION_TIMEOUT);
        Ok(Self { ldap, bound: false })
    }

    /// Binds as `dn` (Novell's `Bind`): an empty password binds anonymously and
    /// leaves [`bound`](Self::bound) `false` — it never authenticates `dn`.
    ///
    /// # Errors
    /// [`ClientError::Ldap`] when the server refuses the bind.
    pub async fn bind(&mut self, dn: &str, password: &str) -> Result<(), ClientError> {
        self.ldap.with_timeout(OPERATION_TIMEOUT);
        if password.is_empty() {
            self.ldap.simple_bind("", "").await?.success()?;
            self.bound = false;
        } else {
            self.ldap.simple_bind(dn, password).await?.success()?;
            self.bound = true;
        }
        Ok(())
    }

    /// Searches the subtree at `base`, following referrals by binding to the
    /// referred server as the bind user (port of `GetSearchConstraints` with
    /// `LdapAuthHandler`). An empty filter matches every entry.
    ///
    /// # Errors
    /// [`ClientError::Ldap`] for a malformed filter or a failed search.
    pub async fn search(
        &mut self,
        config: &LdapConfiguration,
        base: &str,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<Entry>, ClientError> {
        let filter = if filter.is_empty() {
            "(objectClass=*)"
        } else {
            filter
        };
        let mut entries = Vec::new();
        search_following_referrals(&mut self.ldap, config, base, filter, attrs, 0, &mut entries)
            .await?;
        Ok(entries)
    }

    /// Changes `dn`'s password: through the Password Modify extended operation
    /// when the server advertises it, else by replacing `password_attribute`.
    ///
    /// # Errors
    /// [`ClientError::Unsupported`] when the server has no Password Modify and
    /// no attribute is configured; [`ClientError::Ldap`] when the change fails.
    pub async fn change_password(
        &mut self,
        dn: &str,
        new_password: &str,
        password_attribute: &str,
    ) -> Result<(), ClientError> {
        self.ldap.with_timeout(OPERATION_TIMEOUT);
        let (root_dse, _) = self
            .ldap
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec!["supportedExtension"],
            )
            .await?
            .success()?;
        let supports_password_modify = root_dse
            .into_iter()
            .map(|e| Entry::from_search_entry(SearchEntry::construct(e)))
            .any(|e| {
                e.attrs
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("supportedExtension"))
                    .flat_map(|(_, v)| v)
                    .any(|oid| oid == PASSWORD_MODIFY_OID)
            });
        self.ldap.with_timeout(OPERATION_TIMEOUT);
        if supports_password_modify {
            self.ldap
                .extended(PasswordModify {
                    user_id: Some(dn),
                    old_pass: None,
                    new_pass: Some(new_password),
                })
                .await?
                .success()?;
        } else if !password_attribute.is_empty() {
            self.ldap
                .modify(
                    dn,
                    vec![Mod::Replace(
                        password_attribute,
                        HashSet::from([new_password]),
                    )],
                )
                .await?
                .success()?;
        } else {
            return Err(ClientError::Unsupported(
                "Password attribute is not set".to_owned(),
            ));
        }
        Ok(())
    }

    /// Closes the connection.
    pub async fn close(mut self) {
        let _ = self.ldap.unbind().await;
    }
}

/// One search plus the referrals it returned, `hops` deep.
async fn search_following_referrals(
    ldap: &mut Ldap,
    config: &LdapConfiguration,
    base: &str,
    filter: &str,
    attrs: &[&str],
    hops: u8,
    out: &mut Vec<Entry>,
) -> Result<(), ClientError> {
    ldap.with_timeout(OPERATION_TIMEOUT);
    let ldap3::SearchResult(results, result) = ldap
        .search(base, Scope::Subtree, filter, attrs.to_vec())
        .await?;
    let mut referrals = Vec::new();
    for entry in results {
        if entry.is_ref() {
            referrals.extend(ldap3::parse_refs(entry.0));
        } else if !entry.is_intermediate() {
            out.push(Entry::from_search_entry(SearchEntry::construct(entry)));
        }
    }
    match result.rc {
        0 => {}
        // `referral`: the whole search is elsewhere.
        10 => referrals.extend(result.refs.iter().cloned()),
        _ => {
            result.success()?;
        }
    }
    if referrals.is_empty() {
        return Ok(());
    }
    if hops >= MAX_REFERRAL_HOPS {
        tracing::warn!(
            hops,
            "LDAP referral hop limit reached; remaining referrals ignored"
        );
        return Ok(());
    }
    for referral in referrals {
        if let Err(error) =
            follow_referral(config, &referral, base, filter, attrs, hops + 1, out).await
        {
            tracing::warn!(referral = %referral, error = %error, "following an LDAP referral failed");
        }
    }
    Ok(())
}

/// Follows one referral URL: connect to its server, bind as the bind user and
/// repeat the search at the referral's DN (or the original base).
async fn follow_referral(
    config: &LdapConfiguration,
    referral: &str,
    base: &str,
    filter: &str,
    attrs: &[&str],
    hops: u8,
    out: &mut Vec<Entry>,
) -> Result<(), ClientError> {
    let (url, referral_base) = split_referral(referral)
        .ok_or_else(|| ClientError::Unsupported(format!("unusable referral {referral}")))?;
    tracing::debug!(url = %url, bind_dn = %config.ldap_bind_user, "following LDAP referral");
    let mut connection = Connection::open_url(config, &url).await?;
    connection
        .bind(&config.ldap_bind_user, config.ldap_bind_password.expose())
        .await?;
    let base = referral_base.as_deref().unwrap_or(base);
    let result = Box::pin(search_following_referrals(
        &mut connection.ldap,
        config,
        base,
        filter,
        attrs,
        hops,
        out,
    ))
    .await;
    connection.close().await;
    result
}

/// Splits an LDAP URL (`ldap://host:port/dn?…`) into the server URL and its
/// percent-decoded DN, if any.
fn split_referral(referral: &str) -> Option<(String, Option<String>)> {
    let url = reqwest::Url::parse(referral).ok()?;
    if !matches!(url.scheme(), "ldap" | "ldaps") {
        return None;
    }
    let host = url.host_str()?;
    let server = match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    };
    let dn = percent_decode(url.path().trim_start_matches('/'));
    Some((server, (!dn.is_empty()).then_some(dn)))
}

/// Decodes `%XX` escapes (an LDAP URL's DN is percent-encoded UTF-8).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = input.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_follows_the_tls_setting_and_brackets_ipv6() {
        let mut config = LdapConfiguration {
            ldap_server: "ldap.example.org".to_owned(),
            ldap_port: 636,
            ..LdapConfiguration::default()
        };
        assert_eq!(server_url(&config), "ldaps://ldap.example.org:636");
        config.use_ssl = false;
        config.ldap_server = "::1".to_owned();
        config.ldap_port = 389;
        assert_eq!(server_url(&config), "ldap://[::1]:389");
    }

    #[test]
    fn referral_urls_split_into_server_and_dn() {
        assert_eq!(
            split_referral("ldap://dc2.example.org:3268/ou=People,dc=example,dc=org??sub"),
            Some((
                "ldap://dc2.example.org:3268".to_owned(),
                Some("ou=People,dc=example,dc=org".to_owned())
            ))
        );
        assert_eq!(
            split_referral("ldaps://dc2.example.org/"),
            Some(("ldaps://dc2.example.org".to_owned(), None))
        );
        assert_eq!(
            split_referral("ldap://h/cn=J%C3%B6rg,dc=x"),
            Some(("ldap://h".to_owned(), Some("cn=Jörg,dc=x".to_owned())))
        );
        assert_eq!(split_referral("https://example.org/"), None);
        assert_eq!(split_referral("not a url"), None);
    }

    #[test]
    fn percent_decode_leaves_stray_percent_signs() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a%2Cb"), "a,b");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn entry_attributes_ignore_case_and_fall_back_to_binary() {
        let entry = Entry {
            dn: "uid=a,dc=x".to_owned(),
            attrs: HashMap::from([("UID".to_owned(), vec!["a".to_owned()])]),
            bin_attrs: HashMap::from([("jpegPhoto".to_owned(), vec![vec![0xff, 0xd8]])]),
        };
        assert_eq!(entry.text("uid").as_deref(), Some("a"));
        assert_eq!(
            entry.attribute("JPEGPHOTO"),
            Some(AttributeValue::Binary(vec![0xff, 0xd8]))
        );
        assert_eq!(entry.text("jpegphoto"), None);
        assert_eq!(entry.attribute("cn"), None);
    }

    #[test]
    fn default_tls_needs_no_custom_config() {
        let config = LdapConfiguration::default();
        assert!(tls_config(&config).expect("tls").is_none());
        let skip = LdapConfiguration {
            skip_ssl_verify: true,
            ldap_root_ca_path: "/nonexistent.pem".to_owned(),
            ..LdapConfiguration::default()
        };
        // SkipSslVerify wins over the CA, which is then never read.
        assert!(tls_config(&skip).expect("tls").is_none());
    }

    #[test]
    fn a_missing_ca_file_is_a_tls_error() {
        let config = LdapConfiguration {
            ldap_root_ca_path: "/nonexistent/ferrofin-ca.pem".to_owned(),
            ..LdapConfiguration::default()
        };
        assert!(matches!(tls_config(&config), Err(ClientError::Tls(_))));
    }
}
