//! Persistence of the LDAP configuration.
//!
//! Upstream the plugin's `PluginConfiguration` (connection settings plus the
//! `LdapUsers` uid ↔ user links) lives in
//! `{data}/plugins/configurations/LDAP-Auth.xml`. Ferrofin's core provider keeps
//! the same document as JSON in `{config}/ldap.json` (written privately, `0600`,
//! because it holds the bind password). When that file does not exist yet and
//! the Jellyfin plugin's XML does — a Jellyfin data directory being adopted — the
//! XML is imported once, with the provider switched on, so LDAP users keep
//! logging in after the swap. The XML is never written or removed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ferrofin_model::ldap::{LdapConfiguration, LdapUser, ProfileImageFormat};
use ferrofin_model::secret::Secret;
use ferrofin_traits::error::ServiceError;
use serde::Deserialize;
use uuid::Uuid;

/// The file name of the Jellyfin plugin's configuration.
pub const JELLYFIN_PLUGIN_CONFIG_FILE: &str = "LDAP-Auth.xml";

/// The file name of Ferrofin's LDAP configuration.
pub const CONFIG_FILE: &str = "ldap.json";

/// The LDAP configuration and the file it is saved to.
#[derive(Debug)]
pub struct LdapConfigStore {
    path: Option<PathBuf>,
    current: tokio::sync::Mutex<LdapConfiguration>,
    /// Mirrors `current.enabled` for synchronous readers (a task's hidden flag).
    enabled: AtomicBool,
}

impl LdapConfigStore {
    /// An unsaved store holding `config` (tests, and a server without a config
    /// directory).
    #[must_use]
    pub fn in_memory(config: LdapConfiguration) -> Self {
        Self {
            path: None,
            enabled: AtomicBool::new(config.enabled),
            current: tokio::sync::Mutex::new(config),
        }
    }

    /// Loads `{config_dir}/ldap.json`, importing
    /// `{plugin_configurations_dir}/LDAP-Auth.xml` when only that exists, and
    /// the defaults (provider off) when neither does. Runs at boot.
    ///
    /// # Errors
    /// [`ServiceError::Backend`] when an existing file cannot be read or parsed —
    /// a broken LDAP configuration must not boot as "LDAP off" silently.
    pub fn open(config_dir: &Path, plugin_configurations_dir: &Path) -> Result<Self, ServiceError> {
        let path = config_dir.join(CONFIG_FILE);
        let config = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<LdapConfiguration>(&bytes)
                .map_err(|e| ServiceError::backend(format!("parsing {}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let legacy = plugin_configurations_dir.join(JELLYFIN_PLUGIN_CONFIG_FILE);
                match std::fs::read_to_string(&legacy) {
                    Ok(xml) => {
                        let imported = import_jellyfin_xml(&xml).map_err(|e| {
                            ServiceError::backend(format!("parsing {}: {e}", legacy.display()))
                        })?;
                        save(&path, &imported)?;
                        tracing::info!(
                            from = %legacy.display(),
                            to = %path.display(),
                            linked_users = imported.ldap_users.len(),
                            "imported the Jellyfin LDAP-Auth plugin configuration; LDAP authentication is enabled"
                        );
                        imported
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        LdapConfiguration::default()
                    }
                    Err(e) => {
                        return Err(ServiceError::backend(format!(
                            "reading {}: {e}",
                            legacy.display()
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(ServiceError::backend(format!(
                    "reading {}: {e}",
                    path.display()
                )));
            }
        };
        Ok(Self {
            path: Some(path),
            enabled: AtomicBool::new(config.enabled),
            current: tokio::sync::Mutex::new(config),
        })
    }

    /// Whether the provider is switched on, without waiting for the lock.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// A copy of the current configuration.
    pub async fn get(&self) -> LdapConfiguration {
        self.current.lock().await.clone()
    }

    /// Changes the configuration with `change` and saves it; nothing changes when
    /// the save fails.
    ///
    /// # Errors
    /// [`ServiceError::Backend`] when the file cannot be written.
    pub async fn update<R>(
        &self,
        change: impl FnOnce(&mut LdapConfiguration) -> R,
    ) -> Result<R, ServiceError> {
        let mut current = self.current.lock().await;
        let mut next = current.clone();
        let result = change(&mut next);
        if let Some(path) = &self.path {
            let path = path.clone();
            let to_save = next.clone();
            tokio::task::spawn_blocking(move || save(&path, &to_save))
                .await
                .map_err(|e| ServiceError::backend(format!("saving LDAP configuration: {e}")))??;
        }
        self.enabled.store(next.enabled, Ordering::Relaxed);
        *current = next;
        Ok(result)
    }
}

/// Writes `config` to `path` atomically and privately.
fn save(path: &Path, config: &LdapConfiguration) -> Result<(), ServiceError> {
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|e| ServiceError::backend(format!("serializing LDAP configuration: {e}")))?;
    ferrofin_util::file_helper::atomic_write(path, &bytes)
        .map_err(|e| ServiceError::backend(format!("writing {}: {e}", path.display())))
}

/// `LDAP-Auth.xml` as .NET's `XmlSerializer` writes `PluginConfiguration`. Every
/// scalar is read as text and parsed below, so one odd value keeps its default
/// instead of failing the whole import.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct XmlConfiguration {
    ldap_users: XmlLdapUsers,
    ldap_server: Option<String>,
    ldap_port: Option<String>,
    use_ssl: Option<String>,
    use_start_tls: Option<String>,
    skip_ssl_verify: Option<String>,
    ldap_bind_user: Option<String>,
    ldap_bind_password: Option<String>,
    ldap_base_dn: Option<String>,
    ldap_search_filter: Option<String>,
    ldap_admin_base_dn: Option<String>,
    ldap_admin_filter: Option<String>,
    enable_ldap_admin_filter_member_uid: Option<String>,
    ldap_search_attributes: Option<String>,
    ldap_client_cert_path: Option<String>,
    ldap_client_key_path: Option<String>,
    ldap_root_ca_path: Option<String>,
    create_users_from_ldap: Option<String>,
    allow_pass_change: Option<String>,
    ldap_uid_attribute: Option<String>,
    ldap_username_attribute: Option<String>,
    ldap_password_attribute: Option<String>,
    enable_ldap_profile_image_sync: Option<String>,
    remove_images_not_in_ldap: Option<String>,
    ldap_profile_image_attribute: Option<String>,
    ldap_profile_image_format: Option<String>,
    enable_all_folders: Option<String>,
    enabled_folders: XmlStrings,
    password_reset_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct XmlLdapUsers {
    #[serde(rename = "LdapUser")]
    items: Vec<XmlLdapUser>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct XmlLdapUser {
    linked_jellyfin_user_id: Option<String>,
    ldap_uid: Option<String>,
    profile_image_hash: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct XmlStrings {
    #[serde(rename = "string")]
    items: Vec<String>,
}

/// Converts the Jellyfin plugin's XML into a configuration, switched on.
fn import_jellyfin_xml(xml: &str) -> Result<LdapConfiguration, quick_xml::DeError> {
    fn text(value: Option<String>, default: String) -> String {
        value.unwrap_or(default)
    }
    fn flag(value: Option<&str>, default: bool) -> bool {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("true") => true,
            Some(v) if v.eq_ignore_ascii_case("false") => false,
            _ => default,
        }
    }
    let x: XmlConfiguration = quick_xml::de::from_str(xml)?;
    let d = LdapConfiguration::default();
    Ok(LdapConfiguration {
        enabled: true,
        ldap_users: x
            .ldap_users
            .items
            .into_iter()
            .filter_map(|u| {
                Some(LdapUser {
                    linked_jellyfin_user_id: Uuid::parse_str(u.linked_jellyfin_user_id?.trim())
                        .ok()?,
                    ldap_uid: u.ldap_uid.unwrap_or_default(),
                    profile_image_hash: u.profile_image_hash.unwrap_or_default(),
                })
            })
            .collect(),
        ldap_port: x
            .ldap_port
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or(d.ldap_port),
        use_ssl: flag(x.use_ssl.as_deref(), d.use_ssl),
        use_start_tls: flag(x.use_start_tls.as_deref(), d.use_start_tls),
        skip_ssl_verify: flag(x.skip_ssl_verify.as_deref(), d.skip_ssl_verify),
        enable_ldap_admin_filter_member_uid: flag(
            x.enable_ldap_admin_filter_member_uid.as_deref(),
            d.enable_ldap_admin_filter_member_uid,
        ),
        create_users_from_ldap: flag(
            x.create_users_from_ldap.as_deref(),
            d.create_users_from_ldap,
        ),
        allow_pass_change: flag(x.allow_pass_change.as_deref(), d.allow_pass_change),
        enable_ldap_profile_image_sync: flag(
            x.enable_ldap_profile_image_sync.as_deref(),
            d.enable_ldap_profile_image_sync,
        ),
        remove_images_not_in_ldap: flag(
            x.remove_images_not_in_ldap.as_deref(),
            d.remove_images_not_in_ldap,
        ),
        enable_all_folders: flag(x.enable_all_folders.as_deref(), d.enable_all_folders),
        ldap_profile_image_format: match x.ldap_profile_image_format.as_deref().map(str::trim) {
            Some("Binary") => ProfileImageFormat::Binary,
            Some("Base64") => ProfileImageFormat::Base64,
            Some("Url") => ProfileImageFormat::Url,
            _ => ProfileImageFormat::Default,
        },
        ldap_bind_password: x
            .ldap_bind_password
            .map_or(d.ldap_bind_password, Secret::new),
        enabled_folders: x.enabled_folders.items,
        ldap_server: text(x.ldap_server, d.ldap_server),
        ldap_bind_user: text(x.ldap_bind_user, d.ldap_bind_user),
        ldap_base_dn: text(x.ldap_base_dn, d.ldap_base_dn),
        ldap_search_filter: text(x.ldap_search_filter, d.ldap_search_filter),
        ldap_admin_base_dn: text(x.ldap_admin_base_dn, d.ldap_admin_base_dn),
        ldap_admin_filter: text(x.ldap_admin_filter, d.ldap_admin_filter),
        ldap_search_attributes: text(x.ldap_search_attributes, d.ldap_search_attributes),
        ldap_client_cert_path: text(x.ldap_client_cert_path, d.ldap_client_cert_path),
        ldap_client_key_path: text(x.ldap_client_key_path, d.ldap_client_key_path),
        ldap_root_ca_path: text(x.ldap_root_ca_path, d.ldap_root_ca_path),
        ldap_uid_attribute: text(x.ldap_uid_attribute, d.ldap_uid_attribute),
        ldap_username_attribute: text(x.ldap_username_attribute, d.ldap_username_attribute),
        ldap_password_attribute: text(x.ldap_password_attribute, d.ldap_password_attribute),
        ldap_profile_image_attribute: text(
            x.ldap_profile_image_attribute,
            d.ldap_profile_image_attribute,
        ),
        password_reset_url: text(x.password_reset_url, d.password_reset_url),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLUGIN_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<PluginConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <LdapUsers>
    <LdapUser>
      <LinkedJellyfinUserId>5d1f9b8e-4c1a-4a54-9d4a-1f3a5b2c7e90</LinkedJellyfinUserId>
      <LdapUid>alice</LdapUid>
      <ProfileImageHash />
    </LdapUser>
    <LdapUser>
      <LinkedJellyfinUserId>not-a-guid</LinkedJellyfinUserId>
      <LdapUid>broken</LdapUid>
    </LdapUser>
  </LdapUsers>
  <LdapServer>ldap.example.org</LdapServer>
  <LdapPort>636</LdapPort>
  <UseSsl>true</UseSsl>
  <UseStartTls>false</UseStartTls>
  <SkipSslVerify>false</SkipSslVerify>
  <LdapBindUser>cn=svc,dc=example,dc=org</LdapBindUser>
  <LdapBindPassword>s3cret</LdapBindPassword>
  <LdapBaseDn>dc=example,dc=org</LdapBaseDn>
  <LdapSearchFilter>(objectClass=person)</LdapSearchFilter>
  <LdapAdminBaseDn />
  <LdapAdminFilter>_disabled_</LdapAdminFilter>
  <EnableLdapAdminFilterMemberUid>false</EnableLdapAdminFilterMemberUid>
  <LdapSearchAttributes>uid, mail</LdapSearchAttributes>
  <CreateUsersFromLdap>false</CreateUsersFromLdap>
  <AllowPassChange>true</AllowPassChange>
  <LdapUidAttribute>entryUUID</LdapUidAttribute>
  <LdapUsernameAttribute>uid</LdapUsernameAttribute>
  <LdapProfileImageFormat>Base64</LdapProfileImageFormat>
  <EnableAllFolders>false</EnableAllFolders>
  <EnabledFolders>
    <string>f137a2dd21bbc1b99aa5c0f6bf02a805</string>
  </EnabledFolders>
</PluginConfiguration>"#;

    #[test]
    fn the_jellyfin_plugin_xml_imports_switched_on() {
        let c = import_jellyfin_xml(PLUGIN_XML).expect("import");
        assert!(c.enabled);
        assert_eq!(c.ldap_server, "ldap.example.org");
        assert_eq!(c.ldap_port, 636);
        assert_eq!(c.ldap_bind_password.expose(), "s3cret");
        assert!(!c.admin_filter_enabled());
        assert!(!c.create_users_from_ldap);
        assert!(c.allow_pass_change);
        assert_eq!(c.ldap_uid_attribute, "entryUUID");
        assert_eq!(c.ldap_admin_base_dn, "");
        assert_eq!(c.ldap_profile_image_format, ProfileImageFormat::Base64);
        assert_eq!(c.enabled_folders, vec!["f137a2dd21bbc1b99aa5c0f6bf02a805"]);
        // The unparsable link is dropped, the good one kept.
        assert_eq!(c.ldap_users.len(), 1);
        assert_eq!(c.ldap_users[0].ldap_uid, "alice");
        // Absent elements keep the plugin's defaults.
        assert_eq!(c.ldap_password_attribute, "userPassword");
        assert_eq!(c.ldap_profile_image_attribute, "jpegphoto");
    }

    #[tokio::test]
    async fn open_imports_once_then_reads_its_own_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_dir = dir.path().join("config");
        let plugin_dir = dir.path().join("plugins/configurations");
        std::fs::create_dir_all(&plugin_dir).expect("mkdir");
        std::fs::write(plugin_dir.join(JELLYFIN_PLUGIN_CONFIG_FILE), PLUGIN_XML).expect("xml");

        let store = LdapConfigStore::open(&config_dir, &plugin_dir).expect("open");
        assert!(store.get().await.enabled);
        assert!(config_dir.join(CONFIG_FILE).is_file());

        store
            .update(|c| c.ldap_server = "ldap2.example.org".to_owned())
            .await
            .expect("update");
        // The XML is left alone; the JSON now wins.
        let reopened = LdapConfigStore::open(&config_dir, &plugin_dir).expect("reopen");
        assert_eq!(reopened.get().await.ldap_server, "ldap2.example.org");
        assert_eq!(
            std::fs::read_to_string(plugin_dir.join(JELLYFIN_PLUGIN_CONFIG_FILE)).expect("xml"),
            PLUGIN_XML
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(config_dir.join(CONFIG_FILE))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "the bind password must not be world-readable"
            );
        }
    }

    #[tokio::test]
    async fn open_without_any_file_is_off_and_a_broken_file_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LdapConfigStore::open(dir.path(), &dir.path().join("none")).expect("open");
        assert!(!store.get().await.enabled);
        assert!(
            !dir.path().join(CONFIG_FILE).exists(),
            "defaults are not written"
        );

        std::fs::write(dir.path().join(CONFIG_FILE), b"{not json").expect("write");
        assert!(LdapConfigStore::open(dir.path(), dir.path()).is_err());
    }

    #[tokio::test]
    async fn in_memory_updates_apply() {
        let store = LdapConfigStore::in_memory(LdapConfiguration::default());
        let n = store
            .update(|c| {
                c.enabled = true;
                7
            })
            .await
            .expect("update");
        assert_eq!(n, 7);
        assert!(store.get().await.enabled);
        assert!(store.is_enabled());
    }
}
