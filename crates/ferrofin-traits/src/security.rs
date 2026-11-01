//! Security-layer traits — pluggable authentication and Quick Connect.
//!
//! Port of `MediaBrowser.Controller.Authentication.IAuthenticationProvider`
//! (surfaced here as [`AuthenticationManager`]),
//! `MediaBrowser.Controller.Authentication.IPasswordResetProvider`
//! ([`PasswordResetProvider`]) and
//! `MediaBrowser.Controller.QuickConnect.IQuickConnect` ([`QuickConnect`]),
//! plus [`LdapManager`], the administration surface of the core LDAP provider
//! (port of `jellyfin-plugin-ldapauth`'s `LdapController`).
//!
//! Port rules applied throughout:
//! - The C# `User` argument of `ChangePassword` becomes a [`UserEntity`] row;
//!   identity arguments become [`uuid::Uuid`].
//! - `IAuthenticationProvider` folds in the `IRequiresResolvedUser` /
//!   `IHasNewUserPolicy` mixin interfaces: `authenticate` takes an optional
//!   pre-resolved user, and [`AuthenticationManager::new_user_policy`] exposes
//!   the default policy. `ProviderAuthenticationResult` is ported as
//!   [`ProviderAuthenticationResult`].
//! - [`QuickConnect::get_authorized_request`] returns the
//!   [`AuthenticationResultData`] (session and token) of the C#
//!   `AuthenticationResult`; the API layer adds its `User` and `ServerId`.
//! - `Task<T>` → `async fn -> Result<T, ServiceError>`; the `IsEnabled` property
//!   becomes an `async fn` so implementations may consult live configuration.
//!
//! Every trait is object-safe and carries an `_assert_object_safe_*` assertion.

use async_trait::async_trait;
use ferrofin_db::entities::users::UserEntity;
use ferrofin_model::ldap::{
    LdapConfiguration, LdapFilterResponse, ServerConnectionInfo, ServerTestResponse,
    UserFilterInfo, UserSearchAttributes, UserSearchResponse,
};
use ferrofin_model::quick_connect::QuickConnectResult;
use ferrofin_model::security::AuthenticationInfo;
use ferrofin_model::users::{ForgotPasswordResult, UserPolicy};
use uuid::Uuid;

use crate::error::ServiceError;
use crate::options::AuthorizationInfo;
use crate::session::AuthenticationResultData;

/// The result of a successful provider authentication.
///
/// Port of `ProviderAuthenticationResult`: the resolved canonical username plus
/// an optional display name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProviderAuthenticationResult {
    /// The canonical username the credentials resolved to.
    pub username: String,

    /// An optional display name supplied by the provider.
    pub display_name: Option<String>,
}

/// A pluggable authentication backend (built-in, LDAP, …).
///
/// Port of `IAuthenticationProvider` with its `IRequiresResolvedUser` and
/// `IHasNewUserPolicy` mixins folded in. Named "manager" per the Wave 4 port
/// grouping; concrete providers register in `ferrofin-core`.
#[async_trait]
pub trait AuthenticationManager: Send + Sync {
    /// The provider's display name.
    fn name(&self) -> &str;

    /// Whether the provider is currently enabled.
    async fn is_enabled(&self) -> Result<bool, ServiceError>;

    /// Authenticates a username/password pair.
    ///
    /// `resolved_user` carries the already-loaded [`UserEntity`] when the caller
    /// resolved it first (folding in `IRequiresResolvedUser`); providers that do
    /// their own lookup may ignore it.
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
        resolved_user: Option<&UserEntity>,
    ) -> Result<ProviderAuthenticationResult, ServiceError>;

    /// Changes a user's password.
    async fn change_password(
        &self,
        user: &UserEntity,
        new_password: &str,
    ) -> Result<(), ServiceError>;

    /// The default policy to apply to users newly created by this provider, if
    /// it dictates one (folding in `IHasNewUserPolicy`).
    fn new_user_policy(&self) -> Option<UserPolicy>;
}

fn _assert_object_safe_authentication_manager(_: &dyn AuthenticationManager) {}

/// A pluggable password-reset backend besides the built-in pin-file one.
///
/// Port of `IPasswordResetProvider`'s `StartForgotPasswordProcess` half. The
/// built-in `DefaultPasswordResetProvider` lives in the API layer; a user whose
/// `PasswordResetProviderId` names one of these providers is sent here instead.
/// (`RedeemPasswordResetPin` has no counterpart: the only external provider,
/// LDAP, hands the user a reset URL and never issues a pin.)
#[async_trait]
pub trait PasswordResetProvider: Send + Sync {
    /// The provider's display name.
    fn name(&self) -> &str;

    /// The id stored on `User.PasswordResetProviderId` (C# `GetType().FullName`).
    fn id(&self) -> &str;

    /// Whether the provider is currently enabled.
    async fn is_enabled(&self) -> Result<bool, ServiceError>;

    /// Starts a forgot-password process for `user`, who entered `entered_username`.
    async fn start_forgot_password_process(
        &self,
        user: &UserEntity,
        entered_username: &str,
        is_in_network: bool,
    ) -> Result<ForgotPasswordResult, ServiceError>;
}

fn _assert_object_safe_password_reset_provider(_: &dyn PasswordResetProvider) {}

/// Administration of the core LDAP authentication provider.
///
/// Port of `jellyfin-plugin-ldapauth`'s `LdapController` plus the plugin
/// configuration it edits. Each test saves the settings it was given first, as
/// upstream does. Errors follow the controller: a failed connect or bind is
/// [`ServiceError::Unauthorized`] (`401`), an invalid filter
/// [`ServiceError::InvalidInput`] (`400`), each with the message the client shows.
#[async_trait]
pub trait LdapManager: Send + Sync {
    /// The current configuration.
    async fn get_configuration(&self) -> Result<LdapConfiguration, ServiceError>;

    /// Replaces the configuration and saves it.
    async fn update_configuration(&self, config: LdapConfiguration) -> Result<(), ServiceError>;

    /// Saves the connection settings and runs connect → StartTLS → bind → base
    /// search, reporting each step (`TestServerBind`).
    async fn test_server_bind(
        &self,
        info: ServerConnectionInfo,
    ) -> Result<ServerTestResponse, ServiceError>;

    /// Saves the filters and counts the entries each matches (`TestLdapFilters`).
    async fn test_ldap_filters(
        &self,
        info: UserFilterInfo,
    ) -> Result<LdapFilterResponse, ServiceError>;

    /// Saves the search attributes and locates a test username (`LdapUserSearch`).
    async fn ldap_user_search(
        &self,
        body: UserSearchAttributes,
    ) -> Result<UserSearchResponse, ServiceError>;

    /// Synchronises every linked user's profile image from LDAP (the plugin's
    /// `LdapProfileImageSyncTask`); a no-op while image sync is off.
    async fn sync_profile_images(&self) -> Result<(), ServiceError>;
}

fn _assert_object_safe_ldap_manager(_: &dyn LdapManager) {}

/// Drives the Quick Connect pairing flow.
///
/// Port of `IQuickConnect`. The `AuthorizationInfo` initiator argument is the
/// ported [`AuthorizationInfo`] context.
#[async_trait]
pub trait QuickConnect: Send + Sync {
    /// Whether Quick Connect is currently enabled.
    async fn is_enabled(&self) -> Result<bool, ServiceError>;

    /// Initiates a new Quick Connect request for the given initiator.
    async fn try_connect(
        &self,
        authorization_info: &AuthorizationInfo,
    ) -> Result<QuickConnectResult, ServiceError>;

    /// Checks the status of an in-flight request by its secret.
    async fn check_request_status(&self, secret: &str) -> Result<QuickConnectResult, ServiceError>;

    /// Authorizes a request to connect as the given user, by its short code.
    async fn authorize_request(&self, user_id: Uuid, code: &str) -> Result<bool, ServiceError>;

    /// Gets the authentication result (session and access token) opened when
    /// the request's code was authorized (C# `GetAuthorizedRequest`). The
    /// secret exchange returns it as is and never authenticates again.
    async fn get_authorized_request(
        &self,
        secret: &str,
    ) -> Result<AuthenticationResultData, ServiceError>;
}

fn _assert_object_safe_quick_connect(_: &dyn QuickConnect) {}

/// Manages long-lived server API keys.
///
/// Port of the API-key surface of
/// `MediaBrowser.Controller.Security.IAuthenticationManager` (the
/// `GetApiKeys`/`CreateApiKey`/`DeleteApiKey` triple used by `ApiKeyController`).
/// The C# interface's authorization-provider concerns are handled separately by
/// [`AuthenticationManager`]; this trait is the persistence-backed key store.
#[async_trait]
pub trait ApiKeyManager: Send + Sync {
    /// Lists every stored API key as an [`AuthenticationInfo`].
    ///
    /// Mirrors `GetApiKeys`: each key becomes an [`AuthenticationInfo`] whose
    /// `AppName`/`AccessToken`/`DateCreated` come from the key row and whose
    /// device fields are empty.
    async fn get_api_keys(&self) -> Result<Vec<AuthenticationInfo>, ServiceError>;

    /// Creates a new API key named `name`, generating its access token.
    ///
    /// Mirrors `CreateApiKey`: the token is a fresh 32-hex-digit GUID and the
    /// created/last-activity timestamps are set to now.
    async fn create_api_key(&self, name: &str) -> Result<(), ServiceError>;

    /// Deletes the API key whose access token is `access_token` (a no-op when no
    /// key matches). Mirrors `DeleteApiKey`.
    async fn delete_api_key(&self, access_token: &str) -> Result<(), ServiceError>;
}

fn _assert_object_safe_api_key_manager(_: &dyn ApiKeyManager) {}

#[cfg(test)]
mod tests {
    use super::ProviderAuthenticationResult;

    #[test]
    fn provider_result_default_is_empty() {
        let r = ProviderAuthenticationResult::default();
        assert!(r.username.is_empty());
        assert_eq!(r.display_name, None);
    }

    #[test]
    fn provider_result_carries_fields() {
        let r = ProviderAuthenticationResult {
            username: "alice".to_owned(),
            display_name: Some("Alice".to_owned()),
        };
        assert_eq!(r.username, "alice");
        assert_eq!(r.display_name.as_deref(), Some("Alice"));
    }
}
