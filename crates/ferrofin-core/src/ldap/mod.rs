//! The core LDAP authentication provider.
//!
//! Port of [`jellyfin-plugin-ldapauth`](https://github.com/jellyfin/jellyfin-plugin-ldapauth)
//! (`LdapAuthenticationProviderPlugin`, its `LdapController` and
//! `LdapProfileImageSyncTask`). Authentication providers are core surface in
//! Ferrofin, never sandboxed plugins (`docs/EXTENSIONS.md`), so the provider is
//! compiled in and switched on by its configuration
//! ([`LdapConfiguration::enabled`]); its id and name stay the plugin's, so users
//! an adopted Jellyfin database links to the plugin keep logging in.
//!
//! The login flow, as upstream:
//! 1. bind as the configured bind user and locate the entry for the entered
//!    username (search filter AND any search attribute equal to it);
//! 2. find the linked Jellyfin user — by the entry's uid through the stored
//!    `LdapUsers` links, else by its username attribute among the users this
//!    provider owns;
//! 3. bind as the entry's DN with the entered password (an empty password never
//!    authenticates: Novell binds those anonymously, and so does this port);
//! 4. evaluate the administrator filter;
//! 5. create the missing user (when `CreateUsersFromLdap`), or bring an existing
//!    one's name and administrator flag in line with the directory.
//!
//! Every directory failure is an authentication failure
//! ([`ServiceError::Unauthorized`]), which the user manager treats as "this
//! provider did not authenticate the user".

pub mod client;
pub mod filter;
pub mod store;
pub mod task;

use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use ferrofin_db::entities::users::UserEntity;
use ferrofin_model::ldap::{
    LdapConfiguration, LdapFilterResponse, ProfileImageFormat, ServerConnectionInfo,
    ServerTestResponse, UserFilterInfo, UserSearchAttributes, UserSearchResponse,
};
use ferrofin_model::users::{ForgotPasswordAction, ForgotPasswordResult, UserPolicy};
use ferrofin_traits::error::ServiceError;
use ferrofin_traits::library::UserManager;
use ferrofin_traits::security::{
    AuthenticationManager, LdapManager, PasswordResetProvider, ProviderAuthenticationResult,
};
use uuid::Uuid;

use self::client::{AttributeValue, ClientError, Connection, Entry};
pub use self::store::LdapConfigStore;

/// The provider's name (`LdapAuthenticationProviderPlugin.Name`).
pub const LDAP_AUTH_PROVIDER_NAME: &str = "LDAP-Authentication";

/// The provider's id, stored on `User.AuthenticationProviderId` and
/// `User.PasswordResetProviderId` (the plugin's C# type name).
pub const LDAP_AUTH_PROVIDER_ID: &str =
    "Jellyfin.Plugin.LDAP_Auth.LdapAuthenticationProviderPlugin";

/// The largest profile image downloaded from an LDAP-supplied URL.
const MAX_PROFILE_IMAGE_BYTES: usize = 16 * 1024 * 1024;

/// How long a profile image download may take.
const PROFILE_IMAGE_TIMEOUT: Duration = Duration::from_secs(30);

const FAILED_BIND: &str = "Failed to Connect or Bind to server.";
const INVALID_CREDENTIALS: &str = "Error completing LDAP login. Invalid username or password.";

/// The LDAP authentication and password-reset provider.
pub struct LdapAuthenticationProvider {
    store: Arc<LdapConfigStore>,
    users: OnceLock<Weak<dyn UserManager>>,
    http: reqwest::Client,
}

impl std::fmt::Debug for LdapAuthenticationProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapAuthenticationProvider")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl LdapAuthenticationProvider {
    /// Creates the provider over its configuration.
    #[must_use]
    pub fn new(store: Arc<LdapConfigStore>) -> Self {
        Self {
            store,
            users: OnceLock::new(),
            http: reqwest::Client::new(),
        }
    }

    /// Uses `http` for profile images the directory gives as URLs.
    #[must_use]
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Hands the provider the user manager it creates and updates users through.
    ///
    /// The user manager holds the provider, so the provider holds the manager
    /// weakly; the composition root calls this once both exist. Later calls are
    /// ignored.
    pub fn attach_user_manager(&self, users: Weak<dyn UserManager>) {
        let _ = self.users.set(users);
    }

    fn user_manager(&self) -> Result<Arc<dyn UserManager>, ServiceError> {
        self.users
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| ServiceError::backend("the LDAP provider has no user manager attached"))
    }

    /// Connects and binds as the bind user (`ConnectToLdap()`).
    async fn connect_as_bind_user(config: &LdapConfiguration) -> Result<Connection, ServiceError> {
        let result = async {
            let mut connection = Connection::open(config).await?;
            connection
                .bind(&config.ldap_bind_user, config.ldap_bind_password.expose())
                .await?;
            Ok::<_, ClientError>(connection)
        }
        .await;
        result.map_err(|error| {
            tracing::error!(
                bind_dn = %config.ldap_bind_user,
                server = %config.ldap_server,
                error = %error,
                "failed to connect or bind to the LDAP server"
            );
            ServiceError::Unauthorized(FAILED_BIND.to_owned())
        })
    }

    /// Verifies `password` by binding as `dn` (`ConnectToLdap(dn, password)` and
    /// the `Bound` check).
    async fn verify_user_password(
        config: &LdapConfiguration,
        dn: &str,
        password: &str,
    ) -> Result<(), ServiceError> {
        let result = async {
            let mut connection = Connection::open(config).await?;
            connection.bind(dn, password).await?;
            let bound = connection.bound;
            connection.close().await;
            Ok::<_, ClientError>(bound)
        }
        .await;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => {
                tracing::debug!(user_dn = %dn, "LDAP login with an empty password refused");
                Err(ServiceError::Unauthorized(INVALID_CREDENTIALS.to_owned()))
            }
            Err(error) => {
                tracing::debug!(user_dn = %dn, error = %error, "LDAP user bind failed");
                Err(ServiceError::Unauthorized(INVALID_CREDENTIALS.to_owned()))
            }
        }
    }

    /// The attributes a user search asks for.
    fn user_attributes(config: &LdapConfiguration) -> Vec<&str> {
        let mut attrs = vec![
            config.ldap_username_attribute.as_str(),
            config.ldap_uid_attribute.as_str(),
        ];
        if config.enable_ldap_profile_image_sync {
            attrs.push(config.ldap_profile_image_attribute.as_str());
        }
        attrs
    }

    /// Locates the entry for `username` (port of `LocateLdapUser`).
    async fn locate_ldap_user(
        config: &LdapConfiguration,
        username: &str,
    ) -> Result<Entry, ServiceError> {
        let mut connection = Self::connect_as_bind_user(config).await?;
        let search_filter = filter::user_search_filter(
            &config.ldap_search_filter,
            &config.ldap_search_attributes,
            username,
        );
        tracing::debug!(
            base_dn = %config.ldap_base_dn,
            filter = %search_filter,
            server = %config.ldap_server,
            "LDAP user search"
        );
        let found = connection
            .search(
                config,
                &config.ldap_base_dn,
                &search_filter,
                &Self::user_attributes(config),
            )
            .await;
        connection.close().await;
        let mut entries = found.map_err(|error| {
            tracing::error!(filter = %search_filter, error = %error, "LDAP user search failed");
            ServiceError::Unauthorized(
                "Error completing LDAP login while applying user filter.".to_owned(),
            )
        })?;
        if entries.is_empty() {
            tracing::warn!(username, "found no LDAP users matching the username");
            return Err(ServiceError::Unauthorized(
                "Found no LDAP users matching provided username.".to_owned(),
            ));
        }
        if entries.len() > 1 {
            tracing::warn!(
                username,
                matches = entries.len(),
                "more than one LDAP entry matched; using the first only"
            );
        }
        Ok(entries.swap_remove(0))
    }

    /// The DNs `search_filter` matches (port of `GetFilteredUsers`).
    async fn filtered_users(
        config: &LdapConfiguration,
        search_filter: &str,
    ) -> Result<Vec<String>, FilterError> {
        let mut connection = Self::connect_as_bind_user(config)
            .await
            .map_err(FilterError::Connect)?;
        let attrs = [
            config.ldap_username_attribute.as_str(),
            config.ldap_uid_attribute.as_str(),
        ];
        let found = connection
            .search(config, &config.ldap_base_dn, search_filter, &attrs)
            .await;
        connection.close().await;
        found
            .map(|entries| entries.into_iter().map(|e| e.dn).collect())
            .map_err(|error| {
                tracing::warn!(filter = %search_filter, error = %error, "LDAP filter test failed");
                FilterError::Search(error)
            })
    }

    /// Whether the administrator filter makes `entry` an administrator.
    async fn is_ldap_admin(
        config: &LdapConfiguration,
        entry: &Entry,
        ldap_username: &str,
    ) -> Result<bool, ServiceError> {
        if !config.admin_filter_enabled() {
            return Ok(false);
        }
        let mut connection = Self::connect_as_bind_user(config).await?;
        let base = if config.ldap_admin_base_dn.is_empty() {
            &config.ldap_base_dn
        } else {
            &config.ldap_admin_base_dn
        };
        let admin_filter = filter::admin_search_filter(&config.ldap_admin_filter, ldap_username);
        // No attributes wanted: RFC 4511's "1.1" asks for none.
        let found = connection
            .search(config, base, &admin_filter, &["1.1"])
            .await;
        connection.close().await;
        let admins = found.map_err(|error| {
            tracing::error!(filter = %admin_filter, error = %error, "LDAP administrator check failed");
            ServiceError::Unauthorized(
                "Error completing LDAP login while applying admin filter.".to_owned(),
            )
        })?;
        Ok(if config.enable_ldap_admin_filter_member_uid {
            !admins.is_empty()
        } else {
            admins.iter().any(|admin| admin.dn == entry.dn)
        })
    }

    /// The entry's profile image bytes, or `None` when it has none.
    async fn profile_image(
        &self,
        config: &LdapConfiguration,
        entry: &Entry,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        let Some(value) = entry.attribute(&config.ldap_profile_image_attribute) else {
            tracing::debug!(
                attribute = %config.ldap_profile_image_attribute,
                user_dn = %entry.dn,
                "LDAP entry has no profile image attribute"
            );
            return Ok(None);
        };
        let text = match value {
            AttributeValue::Binary(bytes) => return Ok(Some(bytes)),
            AttributeValue::Text(text) => text,
        };
        let format = match config.ldap_profile_image_format {
            ProfileImageFormat::Default => {
                filter::detect_profile_image_format(&text).map_err(ServiceError::InvalidInput)?
            }
            format => format,
        };
        match format {
            ProfileImageFormat::Binary | ProfileImageFormat::Default => Ok(Some(text.into_bytes())),
            ProfileImageFormat::Base64 => filter::decode_base64(&text)
                .map(Some)
                .map_err(|e| ServiceError::invalid_input(format!("LDAP profile image: {e}"))),
            ProfileImageFormat::Url => self.download(&text).await.map(Some),
        }
    }

    /// Downloads a profile image, capped at [`MAX_PROFILE_IMAGE_BYTES`].
    async fn download(&self, url: &str) -> Result<Vec<u8>, ServiceError> {
        let mut response = self
            .http
            .get(url)
            .timeout(PROFILE_IMAGE_TIMEOUT)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| ServiceError::backend(format!("downloading LDAP profile image: {e}")))?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ServiceError::backend(format!("downloading LDAP profile image: {e}")))?
        {
            if bytes.len() + chunk.len() > MAX_PROFILE_IMAGE_BYTES {
                return Err(ServiceError::backend(
                    "the LDAP profile image is larger than 16 MiB",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// The linked Jellyfin user for an entry (steps 2 of the login).
    async fn linked_user(
        &self,
        users: &dyn UserManager,
        config: &LdapConfiguration,
        ldap_uid: Option<&str>,
        ldap_username: &str,
    ) -> Result<Option<UserEntity>, ServiceError> {
        if let Some(link) = ldap_uid.and_then(|uid| config.user_by_uid(uid))
            && let Some(user) = users.get_user_by_id(link.linked_jellyfin_user_id).await?
        {
            return Ok(Some(user));
        }
        // The uid is not linked (or changed): fall back to the username, but only
        // for a user this provider owns.
        let Some(user) = users.get_user_by_name(ldap_username).await? else {
            return Ok(None);
        };
        if !user
            .authentication_provider_id
            .eq_ignore_ascii_case(LDAP_AUTH_PROVIDER_ID)
        {
            return Ok(None);
        }
        let user_id = user_uuid(&user)?;
        let uid = ldap_uid.unwrap_or_default().to_owned();
        self.store.update(|c| c.add_user(user_id, &uid, "")).await?;
        Ok(Some(user))
    }

    /// Creates the Jellyfin user for an authenticated entry.
    async fn create_user(
        &self,
        users: &dyn UserManager,
        config: &LdapConfiguration,
        entry: &Entry,
        ldap_uid: Option<&str>,
        ldap_username: &str,
        is_admin: bool,
    ) -> Result<(), ServiceError> {
        tracing::debug!(username = %ldap_username, is_admin, "creating a user from LDAP");
        let user = users.create_user(ldap_username).await?;
        let user_id = user_uuid(&user)?;
        let mut policy = current_policy(users, &user).await?;
        LDAP_AUTH_PROVIDER_ID.clone_into(&mut policy.authentication_provider_id);
        LDAP_AUTH_PROVIDER_ID.clone_into(&mut policy.password_reset_provider_id);
        policy.is_administrator = is_admin;
        policy.enable_all_folders = config.enable_all_folders;
        if !config.enable_all_folders {
            policy.enabled_folders = config
                .enabled_folders
                .iter()
                .filter_map(|id| {
                    let parsed = Uuid::parse_str(id.trim()).ok();
                    if parsed.is_none() {
                        tracing::warn!(folder = %id, "ignoring an LDAP default folder that is not an id");
                    }
                    parsed
                })
                .collect();
        }
        users.update_policy(user_id, &policy).await?;

        let mut image_hash = String::new();
        if config.enable_ldap_profile_image_sync {
            match self.profile_image(config, entry).await {
                Ok(Some(image)) => {
                    users
                        .save_profile_image(&user, &image, "image/jpeg", ".jpg")
                        .await?;
                    image_hash = filter::profile_image_hash(&image);
                }
                Ok(None) => {}
                // An unusable image never blocks the login it belongs to.
                Err(error) => tracing::warn!(
                    username = %ldap_username,
                    error = %error,
                    "could not set the profile image from LDAP"
                ),
            }
        }
        let uid = ldap_uid.unwrap_or_default().to_owned();
        self.store
            .update(|c| c.add_user(user_id, &uid, &image_hash))
            .await?;
        Ok(())
    }

    /// Brings an existing user's name and administrator flag in line with the
    /// directory.
    async fn update_existing_user(
        users: &dyn UserManager,
        config: &LdapConfiguration,
        user: &UserEntity,
        ldap_username: &str,
        is_admin: bool,
    ) -> Result<(), ServiceError> {
        let user_id = user_uuid(user)?;
        if user.username != ldap_username {
            tracing::debug!(user_id = %user.id, username = %ldap_username, "renaming a user to its LDAP name");
            users
                .rename_user(user_id, &user.username, ldap_username)
                .await?;
        }
        if config.admin_filter_enabled() {
            let mut policy = current_policy(users, user).await?;
            if policy.is_administrator != is_admin {
                tracing::debug!(user_id = %user.id, is_admin, "updating a user's administrator flag from LDAP");
                policy.is_administrator = is_admin;
                users.update_policy(user_id, &policy).await?;
            }
        }
        Ok(())
    }

    /// Synchronises one linked user's profile image; returns the new hash when
    /// it changed.
    async fn sync_profile_image(
        &self,
        users: &dyn UserManager,
        config: &LdapConfiguration,
        link: &ferrofin_model::ldap::LdapUser,
    ) -> Result<Option<String>, ServiceError> {
        let Some(user) = users.get_user_by_id(link.linked_jellyfin_user_id).await? else {
            tracing::debug!(user_id = %link.linked_jellyfin_user_id, "linked LDAP user no longer exists");
            return Ok(None);
        };
        let entry = match Self::locate_ldap_user(config, &link.ldap_uid).await {
            Ok(entry) => entry,
            Err(ServiceError::Unauthorized(_)) => {
                tracing::warn!(ldap_uid = %link.ldap_uid, "user not found in LDAP; cannot synchronise the profile image");
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let user_id = user_uuid(&user)?;
        let has_image = users.get_profile_image(user_id).await?.is_some();
        if let Some(image) = self.profile_image(config, &entry).await? {
            let hash = filter::profile_image_hash(&image);
            if has_image && hash == link.profile_image_hash {
                tracing::debug!(user_id = %user.id, "profile image is already up to date");
                return Ok(None);
            }
            if has_image {
                users.clear_profile_image(&user).await?;
            }
            users
                .save_profile_image(&user, &image, "image/jpeg", ".jpg")
                .await?;
            return Ok(Some(hash));
        }
        if config.remove_images_not_in_ldap && has_image {
            tracing::debug!(user_id = %user.id, "removing a profile image LDAP no longer has");
            users.clear_profile_image(&user).await?;
            return Ok(Some(String::new()));
        }
        Ok(None)
    }
}

/// Why a filter test failed.
enum FilterError {
    /// The bind user could not connect or bind (`401`).
    Connect(ServiceError),
    /// The search failed or the filter is malformed (`400`).
    Search(ClientError),
}

fn user_uuid(user: &UserEntity) -> Result<Uuid, ServiceError> {
    Uuid::parse_str(&user.id)
        .map_err(|e| ServiceError::backend(format!("user id {}: {e}", user.id)))
}

async fn current_policy(
    users: &dyn UserManager,
    user: &UserEntity,
) -> Result<UserPolicy, ServiceError> {
    Ok(users
        .get_user_dto(user, None)
        .await?
        .policy
        .unwrap_or_default())
}

#[async_trait]
impl AuthenticationManager for LdapAuthenticationProvider {
    // The trait fixes the signature to `-> &str`.
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        LDAP_AUTH_PROVIDER_NAME
    }

    async fn is_enabled(&self) -> Result<bool, ServiceError> {
        Ok(self.store.get().await.enabled)
    }

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
        _resolved_user: Option<&UserEntity>,
    ) -> Result<ProviderAuthenticationResult, ServiceError> {
        let config = self.store.get().await;
        let users = self.user_manager()?;
        let entry = Self::locate_ldap_user(&config, username).await?;
        let ldap_uid = entry.text(&config.ldap_uid_attribute);
        if ldap_uid.is_none() {
            tracing::warn!(attribute = %config.ldap_uid_attribute, user_dn = %entry.dn, "LDAP attribute not found");
        }
        let Some(ldap_username) = entry.text(&config.ldap_username_attribute) else {
            tracing::warn!(attribute = %config.ldap_username_attribute, user_dn = %entry.dn, "LDAP attribute not found");
            return Err(ServiceError::Unauthorized(format!(
                "The LDAP entry has no {} attribute to take the username from.",
                config.ldap_username_attribute
            )));
        };
        let user = self
            .linked_user(users.as_ref(), &config, ldap_uid.as_deref(), &ldap_username)
            .await?;

        Self::verify_user_password(&config, &entry.dn, password).await?;
        let is_admin = Self::is_ldap_admin(&config, &entry, &ldap_username).await?;

        match user {
            None if config.create_users_from_ldap => {
                self.create_user(
                    users.as_ref(),
                    &config,
                    &entry,
                    ldap_uid.as_deref(),
                    &ldap_username,
                    is_admin,
                )
                .await?;
            }
            None => {
                tracing::error!(username = %ldap_username, "no user is configured for this LDAP entry");
                return Err(ServiceError::Unauthorized(format!(
                    "Automatic User Creation is disabled and there is no Jellyfin user for authorized Uid: {ldap_username}"
                )));
            }
            Some(user) => {
                Self::update_existing_user(
                    users.as_ref(),
                    &config,
                    &user,
                    &ldap_username,
                    is_admin,
                )
                .await?;
            }
        }
        Ok(ProviderAuthenticationResult {
            username: ldap_username,
            display_name: None,
        })
    }

    async fn change_password(
        &self,
        user: &UserEntity,
        new_password: &str,
    ) -> Result<(), ServiceError> {
        let config = self.store.get().await;
        if !config.allow_pass_change {
            return Err(ServiceError::backend(
                "Changing LDAP passwords is not allowed (AllowPassChange is off).",
            ));
        }
        // Divergence: upstream would hand an empty password (an administrator's
        // "reset password") to the directory. An LDAP account is never emptied.
        if new_password.is_empty() {
            return Err(ServiceError::invalid_input(
                "An LDAP user's password cannot be reset to an empty password.",
            ));
        }
        let entry = Self::locate_ldap_user(&config, &user.username).await?;
        let mut connection = Self::connect_as_bind_user(&config).await?;
        let changed = connection
            .change_password(&entry.dn, new_password, &config.ldap_password_attribute)
            .await;
        connection.close().await;
        changed.map_err(|error| {
            tracing::error!(user_id = %user.id, error = %error, "changing the LDAP password failed");
            ServiceError::backend(format!("Changing the LDAP password failed: {error}"))
        })?;
        tracing::info!(user_id = %user.id, "changed LDAP password");
        Ok(())
    }

    fn new_user_policy(&self) -> Option<UserPolicy> {
        None
    }
}

#[async_trait]
impl PasswordResetProvider for LdapAuthenticationProvider {
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        LDAP_AUTH_PROVIDER_NAME
    }

    #[allow(clippy::unnecessary_literal_bound)]
    fn id(&self) -> &str {
        LDAP_AUTH_PROVIDER_ID
    }

    async fn is_enabled(&self) -> Result<bool, ServiceError> {
        Ok(self.store.get().await.enabled)
    }

    async fn start_forgot_password_process(
        &self,
        user: &UserEntity,
        entered_username: &str,
        _is_in_network: bool,
    ) -> Result<ForgotPasswordResult, ServiceError> {
        let config = self.store.get().await;
        if config.password_reset_url.is_empty() {
            return Err(ServiceError::backend(
                "No password reset URL is configured for LDAP users.",
            ));
        }
        let user_id = user_uuid(user)?.to_string();
        Ok(ForgotPasswordResult {
            action: ForgotPasswordAction::PinCode,
            pin_file: Some(filter::password_reset_url(
                &config.password_reset_url,
                &user_id,
                entered_username,
            )),
            pin_expiration_date: None,
        })
    }
}

#[async_trait]
impl LdapManager for LdapAuthenticationProvider {
    async fn get_configuration(&self) -> Result<LdapConfiguration, ServiceError> {
        Ok(self.store.get().await)
    }

    async fn update_configuration(&self, config: LdapConfiguration) -> Result<(), ServiceError> {
        self.store.update(|c| *c = config).await?;
        tracing::info!("LDAP configuration updated");
        Ok(())
    }

    async fn test_server_bind(
        &self,
        info: ServerConnectionInfo,
    ) -> Result<ServerTestResponse, ServiceError> {
        const STARTED: &str = "Testing...";
        const SUCCESS: &str = "Success";
        let config = self
            .store
            .update(|c| {
                c.ldap_server = info.ldap_server;
                c.ldap_port = info.ldap_port;
                c.use_ssl = info.use_ssl;
                c.use_start_tls = info.use_start_tls;
                c.skip_ssl_verify = info.skip_ssl_verify;
                c.allow_pass_change = info.allow_pass_change;
                c.ldap_bind_user = info.ldap_bind_user;
                c.ldap_bind_password = info.ldap_bind_password;
                c.ldap_base_dn = info.ldap_base_dn;
                c.password_reset_url = info.password_reset_url;
                c.ldap_client_cert_path = info.ldap_client_cert_path;
                c.ldap_client_key_path = info.ldap_client_key_path;
                c.ldap_root_ca_path = info.ldap_root_ca_path;
                c.clone()
            })
            .await?;

        let mut response = ServerTestResponse {
            connect: Some(STARTED.to_owned()),
            ..ServerTestResponse::default()
        };
        if config.use_start_tls {
            response.start_tls = Some(STARTED.to_owned());
        }
        // `ldap3` runs StartTLS as part of the connect, so both steps share it.
        let mut connection = match Connection::open(&config).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(error = %error, "LDAP test failed to connect");
                response.error = Some(error.to_string());
                return Ok(response);
            }
        };
        response.connect = Some(SUCCESS.to_owned());
        if config.use_start_tls {
            response.start_tls = Some(SUCCESS.to_owned());
        }
        let steps = async {
            response.bind = Some(STARTED.to_owned());
            connection
                .bind(&config.ldap_bind_user, config.ldap_bind_password.expose())
                .await?;
            response.bind = Some(
                if connection.bound {
                    SUCCESS
                } else {
                    "Anonymous"
                }
                .to_owned(),
            );
            response.base_search = Some(STARTED.to_owned());
            let found = connection
                .search(&config, &config.ldap_base_dn, "", &["1.1"])
                .await?;
            response.base_search = Some(format!("Found {} Entities", found.len()));
            Ok::<_, ClientError>(())
        }
        .await;
        connection.close().await;
        if let Err(error) = steps {
            tracing::warn!(error = %error, "LDAP test failed to bind or search");
            response.error = Some(error.to_string());
        }
        Ok(response)
    }

    async fn test_ldap_filters(
        &self,
        info: UserFilterInfo,
    ) -> Result<LdapFilterResponse, ServiceError> {
        let config = self
            .store
            .update(|c| {
                c.ldap_search_filter = info.ldap_search_filter;
                c.ldap_admin_filter = info.ldap_admin_filter;
                c.enable_ldap_admin_filter_member_uid = info.enable_ldap_admin_filter_member_uid;
                c.clone()
            })
            .await?;
        let filter_error = |label: &str, error: FilterError| match error {
            FilterError::Connect(error) => error,
            FilterError::Search(error) => ServiceError::InvalidInput(format!("{label}{error}")),
        };
        let users: std::collections::HashSet<String> =
            Self::filtered_users(&config, &config.ldap_search_filter)
                .await
                .map_err(|e| filter_error("User Filter: ", e))?
                .into_iter()
                .collect();
        let admins: std::collections::HashSet<String> = if config.admin_filter_enabled() {
            Self::filtered_users(&config, &config.ldap_admin_filter)
                .await
                .map_err(|e| filter_error("Admin Filter: ", e))?
                .into_iter()
                .collect()
        } else {
            std::collections::HashSet::new()
        };
        Ok(LdapFilterResponse {
            users: users.len(),
            admins: admins.len(),
            is_subset: admins.is_subset(&users),
        })
    }

    async fn ldap_user_search(
        &self,
        body: UserSearchAttributes,
    ) -> Result<UserSearchResponse, ServiceError> {
        let config = self
            .store
            .update(|c| {
                c.ldap_search_attributes = body.ldap_search_attributes;
                c.clone()
            })
            .await?;
        if body.test_search_username.is_empty() {
            return Ok(UserSearchResponse::default());
        }
        let entry = Self::locate_ldap_user(&config, &body.test_search_username).await?;
        Ok(UserSearchResponse {
            located_dn: Some(entry.dn),
        })
    }

    async fn sync_profile_images(&self) -> Result<(), ServiceError> {
        let config = self.store.get().await;
        if !config.enabled || !config.enable_ldap_profile_image_sync {
            tracing::debug!("LDAP profile image sync is off");
            return Ok(());
        }
        let users = self.user_manager()?;
        let mut changed = Vec::new();
        for link in &config.ldap_users {
            match self.sync_profile_image(users.as_ref(), &config, link).await {
                Ok(Some(hash)) => changed.push((link.linked_jellyfin_user_id, hash)),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    user_id = %link.linked_jellyfin_user_id,
                    error = %error,
                    "synchronising a profile image from LDAP failed"
                ),
            }
        }
        if !changed.is_empty() {
            self.store
                .update(|c| {
                    for (user_id, hash) in changed {
                        if let Some(link) = c
                            .ldap_users
                            .iter_mut()
                            .find(|u| u.linked_jellyfin_user_id == user_id)
                        {
                            link.profile_image_hash = hash;
                        }
                    }
                })
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
