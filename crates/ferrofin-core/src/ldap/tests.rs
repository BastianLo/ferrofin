//! Unit tests of the LDAP provider that need no directory server; the
//! end-to-end flow against a real `slapd` is `tests/ldap_slapd.rs`.

use std::sync::Arc;

use ferrofin_model::ldap::{
    LdapConfiguration, ServerConnectionInfo, UserFilterInfo, UserSearchAttributes,
};
use ferrofin_model::secret::Secret;
use ferrofin_traits::error::ServiceError;
use ferrofin_traits::library::UserManager;
use ferrofin_traits::security::{AuthenticationManager, LdapManager, PasswordResetProvider};
use uuid::Uuid;

use super::{
    LDAP_AUTH_PROVIDER_ID, LDAP_AUTH_PROVIDER_NAME, LdapAuthenticationProvider, LdapConfigStore,
};
use crate::FerrofinUserManager;
use crate::test_support::{seed_user, test_db};

/// A port nothing listens on: bound, then released.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// An enabled configuration pointing at a closed local port.
fn unreachable_config() -> LdapConfiguration {
    LdapConfiguration {
        enabled: true,
        ldap_server: "127.0.0.1".to_owned(),
        ldap_port: closed_port(),
        use_ssl: false,
        ..LdapConfiguration::default()
    }
}

fn provider(config: LdapConfiguration) -> Arc<LdapAuthenticationProvider> {
    Arc::new(LdapAuthenticationProvider::new(Arc::new(
        LdapConfigStore::in_memory(config),
    )))
}

/// A user manager with the LDAP provider registered and attached.
async fn manager_with(
    ldap: &Arc<LdapAuthenticationProvider>,
) -> (Arc<dyn UserManager>, ferrofin_db::Database) {
    let db = test_db().await;
    let users: Arc<dyn UserManager> = Arc::new(
        FerrofinUserManager::with_providers(
            db.clone(),
            vec![Arc::clone(ldap) as Arc<dyn AuthenticationManager>],
        )
        .with_password_reset_providers(vec![Arc::clone(ldap) as Arc<dyn PasswordResetProvider>]),
    );
    ldap.attach_user_manager(Arc::downgrade(&users));
    (users, db)
}

#[tokio::test]
async fn identity_matches_the_upstream_plugin() {
    let ldap = provider(LdapConfiguration::default());
    assert_eq!(
        AuthenticationManager::name(ldap.as_ref()),
        LDAP_AUTH_PROVIDER_NAME
    );
    assert_eq!(
        PasswordResetProvider::name(ldap.as_ref()),
        LDAP_AUTH_PROVIDER_NAME
    );
    assert_eq!(ldap.id(), LDAP_AUTH_PROVIDER_ID);
    assert!(
        !AuthenticationManager::is_enabled(ldap.as_ref())
            .await
            .expect("enabled")
    );
    assert!(ldap.new_user_policy().is_none());
    assert!(format!("{ldap:?}").contains("LdapAuthenticationProvider"));
}

#[tokio::test]
async fn providers_are_listed_only_while_enabled() {
    let ldap = provider(LdapConfiguration::default());
    let (users, _db) = manager_with(&ldap).await;
    let ids = |pairs: Vec<ferrofin_model::dto::NameIdPair>| {
        pairs.into_iter().filter_map(|p| p.id).collect::<Vec<_>>()
    };
    assert_eq!(
        ids(users.get_authentication_providers().await.expect("list")).len(),
        1
    );
    assert_eq!(
        ids(users.get_password_reset_providers().await.expect("list")).len(),
        1
    );

    ldap.update_configuration(LdapConfiguration {
        enabled: true,
        ..LdapConfiguration::default()
    })
    .await
    .expect("enable");
    let auth = ids(users.get_authentication_providers().await.expect("list"));
    assert_eq!(auth[0], crate::auth_providers::DEFAULT_AUTH_PROVIDER_ID);
    assert_eq!(auth[1], LDAP_AUTH_PROVIDER_ID);
    let reset = ids(users.get_password_reset_providers().await.expect("list"));
    assert_eq!(reset[1], LDAP_AUTH_PROVIDER_ID);
}

#[tokio::test]
async fn an_unreachable_directory_is_an_authentication_failure() {
    let ldap = provider(unreachable_config());
    let (users, _db) = manager_with(&ldap).await;
    let err = ldap
        .authenticate("alice", "pw", None)
        .await
        .expect_err("no server");
    assert!(matches!(err, ServiceError::Unauthorized(m) if m == super::FAILED_BIND));

    // Through the manager: an unknown user, no provider succeeds.
    let err = users
        .authenticate_user("alice", "pw", "127.0.0.1", true)
        .await
        .expect_err("refused");
    assert!(matches!(err, ServiceError::Unauthorized(_)), "{err:?}");
}

#[tokio::test]
async fn without_a_user_manager_the_provider_fails_loudly() {
    let ldap = provider(unreachable_config());
    let err = ldap
        .authenticate("alice", "pw", None)
        .await
        .expect_err("no manager");
    assert!(matches!(err, ServiceError::Backend(_)), "{err:?}");
    assert!(matches!(
        ldap.sync_profile_images().await,
        Ok(()) // sync is off by default, so it never needs the manager
    ));
}

#[tokio::test]
async fn a_local_user_is_never_handed_to_ldap() {
    let ldap = provider(unreachable_config());
    let (users, db) = manager_with(&ldap).await;
    let id = Uuid::new_v4();
    let user = seed_user(&db, id).await;
    // The seeded user belongs to the default provider: only it is asked, so a
    // dead directory does not matter and a wrong password is a plain failure.
    let result = users
        .authenticate_user(&user.username, "wrong", "127.0.0.1", true)
        .await
        .expect("evaluated");
    assert!(result.is_none());
}

#[tokio::test]
async fn forgot_password_hands_out_the_reset_url() {
    let db = test_db().await;
    let user = seed_user(&db, Uuid::new_v4()).await;
    let ldap = provider(LdapConfiguration::default());
    assert!(matches!(
        ldap.start_forgot_password_process(&user, "Alice", true)
            .await,
        Err(ServiceError::Backend(_))
    ));
    ldap.update_configuration(LdapConfiguration {
        password_reset_url: "https://id.example/r?u=$userName&i=$userId".to_owned(),
        ..LdapConfiguration::default()
    })
    .await
    .expect("save");
    let result = ldap
        .start_forgot_password_process(&user, "Alice", true)
        .await
        .expect("url");
    let uid = Uuid::parse_str(&user.id).expect("id").to_string();
    assert_eq!(
        result.pin_file.as_deref(),
        Some(format!("https://id.example/r?u=alice&i={uid}").as_str())
    );
    assert_eq!(
        result.action,
        ferrofin_model::users::ForgotPasswordAction::PinCode
    );
    assert!(result.pin_expiration_date.is_none());
}

#[tokio::test]
async fn password_changes_need_allow_pass_change_and_a_password() {
    let db = test_db().await;
    let user = seed_user(&db, Uuid::new_v4()).await;
    let ldap = provider(unreachable_config());
    assert!(matches!(
        ldap.change_password(&user, "new").await,
        Err(ServiceError::Backend(_))
    ));
    ldap.update_configuration(LdapConfiguration {
        allow_pass_change: true,
        ..unreachable_config()
    })
    .await
    .expect("save");
    assert!(matches!(
        ldap.change_password(&user, "").await,
        Err(ServiceError::InvalidInput(_))
    ));
    // Allowed, but the directory is down.
    assert!(matches!(
        ldap.change_password(&user, "new").await,
        Err(ServiceError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn tests_save_their_settings_first() {
    let ldap = provider(unreachable_config());
    let port = closed_port();
    let response = ldap
        .test_server_bind(ServerConnectionInfo {
            ldap_server: "127.0.0.1".to_owned(),
            ldap_port: port,
            use_start_tls: true,
            ldap_bind_password: Secret::new("pw"),
            ..ServerConnectionInfo::default()
        })
        .await
        .expect("report");
    assert_eq!(response.connect.as_deref(), Some("Testing..."));
    assert_eq!(response.start_tls.as_deref(), Some("Testing..."));
    assert!(response.bind.is_none());
    assert!(response.error.is_some());
    let saved = ldap.get_configuration().await.expect("config");
    assert_eq!(saved.ldap_port, port);
    assert!(saved.use_start_tls);
    assert_eq!(saved.ldap_bind_password.expose(), "pw");

    let err = ldap
        .test_ldap_filters(UserFilterInfo {
            ldap_search_filter: "(uid=*)".to_owned(),
            ldap_admin_filter: "_disabled_".to_owned(),
            enable_ldap_admin_filter_member_uid: true,
        })
        .await
        .expect_err("no server");
    assert!(matches!(err, ServiceError::Unauthorized(_)));
    let saved = ldap.get_configuration().await.expect("config");
    assert_eq!(saved.ldap_search_filter, "(uid=*)");
    assert!(saved.enable_ldap_admin_filter_member_uid);

    let found = ldap
        .ldap_user_search(UserSearchAttributes {
            ldap_search_attributes: "uid,mail".to_owned(),
            test_search_username: String::new(),
        })
        .await
        .expect("nothing to search");
    assert!(found.located_dn.is_none());
    assert_eq!(
        ldap.get_configuration()
            .await
            .expect("config")
            .ldap_search_attributes,
        "uid,mail"
    );
    assert!(matches!(
        ldap.ldap_user_search(UserSearchAttributes {
            ldap_search_attributes: "uid".to_owned(),
            test_search_username: "bob".to_owned(),
        })
        .await,
        Err(ServiceError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn the_task_is_hidden_while_ldap_is_off() {
    use crate::scheduled_tasks::ScheduledTask as _;
    let store = Arc::new(LdapConfigStore::in_memory(LdapConfiguration::default()));
    let ldap = Arc::new(LdapAuthenticationProvider::new(Arc::clone(&store)));
    let task = super::task::LdapProfileImageSyncTask::new(
        Arc::clone(&ldap) as Arc<dyn LdapManager>,
        Arc::clone(&store),
    );
    assert_eq!(task.key(), "LdapProfileImageSync");
    assert_eq!(task.name(), "LDAP - Synchronize profile images");
    assert_eq!(task.category(), "Application");
    assert!(!task.description().is_empty());
    assert!(task.is_configurable());
    assert!(task.is_hidden());
    assert_eq!(task.default_triggers().len(), 1);
    store.update(|c| c.enabled = true).await.expect("enable");
    assert!(!task.is_hidden());
    task.execute(&crate::scheduled_tasks::TaskProgress::default())
        .await
        .expect("sync off is a no-op");
}
