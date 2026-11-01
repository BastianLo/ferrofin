//! LDAP authentication DTOs.
//!
//! Port of the configuration and API models of
//! [`jellyfin-plugin-ldapauth`](https://github.com/jellyfin/jellyfin-plugin-ldapauth)
//! (`Config/PluginConfiguration.cs`, `Config/ProfileImageFormat.cs` and
//! `Api/Models/*.cs`). In Ferrofin LDAP is a core authentication provider, not a
//! plugin (`docs/EXTENSIONS.md`), but the field names, casing and defaults stay
//! those of the upstream plugin so an administrator's knowledge (and their
//! `LDAP-Auth.xml`) carries over unchanged.
//!
//! One field is Ferrofin's own: [`LdapConfiguration::enabled`]. Upstream the
//! provider is active whenever the plugin is installed; a core provider is always
//! compiled in, so it is switched on by configuration instead and is off until an
//! administrator turns it on.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::secret::Secret;

/// How the profile image attribute of an LDAP entry is encoded.
///
/// Port of `ProfileImageFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub enum ProfileImageFormat {
    /// Detect the format from the attribute value (binary, Base64 or URL).
    #[default]
    Default,
    /// The attribute holds the raw image bytes.
    Binary,
    /// The attribute holds the image as Base64 text.
    Base64,
    /// The attribute holds an `http(s)` URL the image is downloaded from.
    Url,
}

/// The link between a Jellyfin user and its LDAP entry.
///
/// Port of `Api/Models/LdapUser.cs`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase", default)]
pub struct LdapUser {
    /// The id of the linked Jellyfin user.
    #[schema(value_type = String, format = "uuid")]
    pub linked_jellyfin_user_id: Uuid,
    /// The value of the entry's uid attribute ([`LdapConfiguration::ldap_uid_attribute`]).
    pub ldap_uid: String,
    /// The Base64 MD5 of the profile image last synchronised from LDAP.
    pub profile_image_hash: String,
}

/// The LDAP authentication provider's configuration.
///
/// Port of `Config/PluginConfiguration.cs`, with the same defaults.
// The upstream plugin's shape: one flag per setting.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase", default)]
pub struct LdapConfiguration {
    /// Whether the LDAP provider is active (Ferrofin's own switch; upstream the
    /// provider is active while the plugin is installed).
    pub enabled: bool,
    /// The users linked to LDAP entries.
    pub ldap_users: Vec<LdapUser>,
    /// The LDAP server host name or address.
    pub ldap_server: String,
    /// The LDAP server port.
    pub ldap_port: u16,
    /// Whether to connect with TLS (`ldaps://`).
    pub use_ssl: bool,
    /// Whether to upgrade a plain connection with StartTLS.
    pub use_start_tls: bool,
    /// Whether to skip verification of the server certificate.
    pub skip_ssl_verify: bool,
    /// The DN of the user the server binds as to search.
    pub ldap_bind_user: String,
    /// The bind user's password.
    #[schema(value_type = String)]
    pub ldap_bind_password: Secret,
    /// The base DN user searches start at.
    pub ldap_base_dn: String,
    /// The filter a user must match to log in.
    pub ldap_search_filter: String,
    /// The base DN of the administrator search; empty uses [`Self::ldap_base_dn`].
    pub ldap_admin_base_dn: String,
    /// The filter that makes a user an administrator; empty or `_disabled_` turns
    /// the administrator mapping off.
    pub ldap_admin_filter: String,
    /// Whether any match of the administrator filter (rather than a match of the
    /// user's own DN) makes the user an administrator — for `memberUid` groups.
    pub enable_ldap_admin_filter_member_uid: bool,
    /// The comma-separated attributes the entered username is matched against.
    pub ldap_search_attributes: String,
    /// The PEM client certificate presented to the server.
    pub ldap_client_cert_path: String,
    /// The PEM private key of [`Self::ldap_client_cert_path`].
    pub ldap_client_key_path: String,
    /// A PEM CA bundle that replaces the system roots for the server certificate.
    pub ldap_root_ca_path: String,
    /// Whether a successful LDAP login creates the missing Jellyfin user.
    pub create_users_from_ldap: bool,
    /// Whether users may change their LDAP password (needs a privileged bind user).
    pub allow_pass_change: bool,
    /// The attribute that identifies an entry for good.
    pub ldap_uid_attribute: String,
    /// The attribute that becomes the Jellyfin username.
    pub ldap_username_attribute: String,
    /// The attribute a password change writes when the server has no Password
    /// Modify extended operation.
    pub ldap_password_attribute: String,
    /// Whether profile images are synchronised from LDAP.
    pub enable_ldap_profile_image_sync: bool,
    /// Whether a profile image is removed once LDAP no longer has one.
    pub remove_images_not_in_ldap: bool,
    /// The attribute that holds the profile image.
    pub ldap_profile_image_attribute: String,
    /// How [`Self::ldap_profile_image_attribute`] is encoded.
    pub ldap_profile_image_format: ProfileImageFormat,
    /// Whether users created from LDAP may access every library.
    pub enable_all_folders: bool,
    /// The libraries users created from LDAP may access, when not all.
    pub enabled_folders: Vec<String>,
    /// The page a user is sent to to reset their password (`$userId` and
    /// `$userName` are replaced); empty disables password reset for LDAP users.
    pub password_reset_url: String,
}

impl Default for LdapConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            ldap_users: Vec::new(),
            ldap_server: "ldap-server.contoso.com".to_owned(),
            ldap_port: 389,
            use_ssl: true,
            use_start_tls: false,
            skip_ssl_verify: false,
            ldap_bind_user: "CN=BindUser,DC=contoso,DC=com".to_owned(),
            ldap_bind_password: Secret::new("password"),
            ldap_base_dn: "o=domains,dc=contoso,dc=com".to_owned(),
            ldap_search_filter: "(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)".to_owned(),
            ldap_admin_base_dn: String::new(),
            ldap_admin_filter: "(enabledService=JellyfinAdministrator)".to_owned(),
            enable_ldap_admin_filter_member_uid: false,
            ldap_search_attributes: "uid, cn, mail, displayName".to_owned(),
            ldap_client_cert_path: String::new(),
            ldap_client_key_path: String::new(),
            ldap_root_ca_path: String::new(),
            create_users_from_ldap: true,
            allow_pass_change: false,
            ldap_uid_attribute: "uid".to_owned(),
            ldap_username_attribute: "cn".to_owned(),
            ldap_password_attribute: "userPassword".to_owned(),
            enable_ldap_profile_image_sync: false,
            remove_images_not_in_ldap: false,
            ldap_profile_image_attribute: "jpegphoto".to_owned(),
            ldap_profile_image_format: ProfileImageFormat::Default,
            enable_all_folders: false,
            enabled_folders: Vec::new(),
            password_reset_url: String::new(),
        }
    }
}

impl LdapConfiguration {
    /// Links `user_id` to the LDAP entry `ldap_uid`, replacing any earlier link of
    /// either (port of `PluginConfiguration.AddUser`).
    pub fn add_user(&mut self, user_id: Uuid, ldap_uid: &str, profile_image_hash: &str) {
        self.ldap_users
            .retain(|u| u.linked_jellyfin_user_id != user_id && u.ldap_uid != ldap_uid);
        self.ldap_users.push(LdapUser {
            linked_jellyfin_user_id: user_id,
            ldap_uid: ldap_uid.to_owned(),
            profile_image_hash: profile_image_hash.to_owned(),
        });
    }

    /// The link for the LDAP entry `ldap_uid` (port of `UserHelper.GetLdapUser(string)`).
    #[must_use]
    pub fn user_by_uid(&self, ldap_uid: &str) -> Option<&LdapUser> {
        self.ldap_users
            .iter()
            .find(|u| !u.ldap_uid.is_empty() && u.ldap_uid == ldap_uid)
    }

    /// Whether an administrator filter is configured (not empty, not `_disabled_`).
    #[must_use]
    pub fn admin_filter_enabled(&self) -> bool {
        !self.ldap_admin_filter.is_empty() && self.ldap_admin_filter != "_disabled_"
    }
}

/// The connection settings `POST /Ldap/TestServerBind` saves and tests.
///
/// Port of `Api/Models/ServerConnectionInfo.cs`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase", default)]
pub struct ServerConnectionInfo {
    /// See [`LdapConfiguration::ldap_server`].
    pub ldap_server: String,
    /// See [`LdapConfiguration::ldap_port`].
    pub ldap_port: u16,
    /// See [`LdapConfiguration::use_ssl`].
    pub use_ssl: bool,
    /// See [`LdapConfiguration::use_start_tls`].
    pub use_start_tls: bool,
    /// See [`LdapConfiguration::skip_ssl_verify`].
    pub skip_ssl_verify: bool,
    /// See [`LdapConfiguration::allow_pass_change`].
    pub allow_pass_change: bool,
    /// See [`LdapConfiguration::ldap_bind_user`].
    pub ldap_bind_user: String,
    /// See [`LdapConfiguration::ldap_bind_password`].
    #[schema(value_type = String)]
    pub ldap_bind_password: Secret,
    /// See [`LdapConfiguration::ldap_base_dn`].
    pub ldap_base_dn: String,
    /// See [`LdapConfiguration::password_reset_url`].
    pub password_reset_url: String,
    /// See [`LdapConfiguration::ldap_client_cert_path`].
    pub ldap_client_cert_path: String,
    /// See [`LdapConfiguration::ldap_client_key_path`].
    pub ldap_client_key_path: String,
    /// See [`LdapConfiguration::ldap_root_ca_path`].
    pub ldap_root_ca_path: String,
}

/// Each step of a server test (`Testing...`, `Success`, or the step's result).
///
/// Port of `Api/Models/ServerTestResponse.cs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct ServerTestResponse {
    /// The connection step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<String>,
    /// The StartTLS step, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_tls: Option<String>,
    /// The bind step (`Success`, or `Anonymous` for an anonymous bind).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// The base search step (`Found {n} Entities`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_search: Option<String>,
    /// The error that ended the test, if one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The filters `POST /Ldap/TestLdapFilters` saves and tests.
///
/// Port of `Api/Models/UserFilterInfo.cs`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase", default)]
pub struct UserFilterInfo {
    /// See [`LdapConfiguration::ldap_search_filter`].
    pub ldap_search_filter: String,
    /// See [`LdapConfiguration::ldap_admin_filter`].
    pub ldap_admin_filter: String,
    /// See [`LdapConfiguration::enable_ldap_admin_filter_member_uid`].
    pub enable_ldap_admin_filter_member_uid: bool,
}

/// How many entries the user and administrator filters match.
///
/// Port of `Api/Models/LdapFilterResponse.cs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct LdapFilterResponse {
    /// Entries the user filter matched.
    pub users: usize,
    /// Entries the administrator filter matched.
    pub admins: usize,
    /// Whether every administrator is also a user.
    pub is_subset: bool,
}

/// The search attributes `POST /Ldap/LdapUserSearch` saves, and a username to
/// look up with them.
///
/// Port of `Api/Models/UserSearchAttributes.cs`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase", default)]
pub struct UserSearchAttributes {
    /// See [`LdapConfiguration::ldap_search_attributes`].
    pub ldap_search_attributes: String,
    /// The username to look up; empty only saves the attributes.
    pub test_search_username: String,
}

/// The DN a test username resolved to.
///
/// Port of `Api/Models/UserSearchResponse.cs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct UserSearchResponse {
    /// The DN of the located entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub located_dn: Option<String>,
}

/// The body of a failed LDAP test.
///
/// Port of `Api/Models/LdapTestErrorResponse.cs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub struct LdapTestErrorResponse {
    /// What went wrong.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_upstream_plugin() {
        let c = LdapConfiguration::default();
        assert!(!c.enabled);
        assert_eq!(c.ldap_port, 389);
        assert!(c.use_ssl);
        assert!(c.create_users_from_ldap);
        assert_eq!(c.ldap_search_attributes, "uid, cn, mail, displayName");
        assert_eq!(c.ldap_uid_attribute, "uid");
        assert_eq!(c.ldap_username_attribute, "cn");
        assert_eq!(c.ldap_profile_image_attribute, "jpegphoto");
        assert!(c.admin_filter_enabled());
    }

    #[test]
    fn json_is_pascal_case_and_sparse_input_keeps_defaults() {
        let c: LdapConfiguration =
            serde_json::from_str(r#"{"Enabled":true,"LdapServer":"ldap.example.org"}"#)
                .expect("parse");
        assert!(c.enabled);
        assert_eq!(c.ldap_server, "ldap.example.org");
        assert_eq!(c.ldap_port, 389);
        let json = serde_json::to_value(&c).expect("serialize");
        assert_eq!(json["LdapBindPassword"], "password");
        assert_eq!(json["LdapProfileImageFormat"], "Default");
    }

    #[test]
    fn add_user_replaces_earlier_links_of_either_side() {
        let mut c = LdapConfiguration::default();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        c.add_user(a, "alice", "");
        c.add_user(b, "bob", "");
        // `a` now links to bob's uid: both old links go.
        c.add_user(a, "bob", "hash");
        assert_eq!(c.ldap_users.len(), 1);
        assert_eq!(
            c.user_by_uid("bob").map(|u| u.linked_jellyfin_user_id),
            Some(a)
        );
        assert!(c.user_by_uid("alice").is_none());
        assert!(c.user_by_uid("").is_none());
    }

    #[test]
    fn admin_filter_can_be_disabled() {
        let mut c = LdapConfiguration {
            ldap_admin_filter: "_disabled_".to_owned(),
            ..LdapConfiguration::default()
        };
        assert!(!c.admin_filter_enabled());
        c.ldap_admin_filter = String::new();
        assert!(!c.admin_filter_enabled());
    }
}
