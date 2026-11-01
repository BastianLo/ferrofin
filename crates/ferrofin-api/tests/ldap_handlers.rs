//! `/Ldap/*` handler tests: the administrator gate, the unwired `503`, and the
//! plugin's response shapes, over a fake [`LdapManager`].

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferrofin_api::create_router;
use ferrofin_api::state::AppState;
use ferrofin_api::test_support::{authed_fake_state, elevated_fake_state};
use ferrofin_model::ldap::{
    LdapConfiguration, LdapFilterResponse, ServerConnectionInfo, ServerTestResponse,
    UserFilterInfo, UserSearchAttributes, UserSearchResponse,
};
use ferrofin_traits::error::ServiceError;
use ferrofin_traits::security::LdapManager;
use serde_json::Value;
use tower::ServiceExt;

#[derive(Default)]
struct FakeLdap {
    config: Mutex<LdapConfiguration>,
}

#[async_trait]
impl LdapManager for FakeLdap {
    async fn get_configuration(&self) -> Result<LdapConfiguration, ServiceError> {
        Ok(self.config.lock().expect("lock").clone())
    }
    async fn update_configuration(&self, config: LdapConfiguration) -> Result<(), ServiceError> {
        *self.config.lock().expect("lock") = config;
        Ok(())
    }
    async fn test_server_bind(
        &self,
        info: ServerConnectionInfo,
    ) -> Result<ServerTestResponse, ServiceError> {
        Ok(ServerTestResponse {
            connect: Some("Success".to_owned()),
            bind: Some(info.ldap_bind_user),
            ..ServerTestResponse::default()
        })
    }
    async fn test_ldap_filters(
        &self,
        info: UserFilterInfo,
    ) -> Result<LdapFilterResponse, ServiceError> {
        if info.ldap_search_filter.ends_with(')') {
            Ok(LdapFilterResponse {
                users: 2,
                admins: 1,
                is_subset: true,
            })
        } else {
            Err(ServiceError::InvalidInput(
                "User Filter: filter parse error".to_owned(),
            ))
        }
    }
    async fn ldap_user_search(
        &self,
        _body: UserSearchAttributes,
    ) -> Result<UserSearchResponse, ServiceError> {
        Err(ServiceError::Unauthorized(
            "Found no LDAP users matching provided username.".to_owned(),
        ))
    }
    async fn sync_profile_images(&self) -> Result<(), ServiceError> {
        Ok(())
    }
}

async fn call(
    state: AppState,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .expect("request");
    let response = create_router(state)
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn wired(ldap: &Arc<FakeLdap>) -> AppState {
    elevated_fake_state().with_ldap(Arc::clone(ldap) as Arc<dyn LdapManager>)
}

#[tokio::test]
async fn unwired_ldap_is_unavailable() {
    let (status, _) = call(elevated_fake_state(), "GET", "/Ldap/Configuration", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_routes_need_an_administrator() {
    let ldap = Arc::new(FakeLdap::default());
    let state = authed_fake_state().with_ldap(Arc::clone(&ldap) as Arc<dyn LdapManager>);
    let (status, _) = call(state, "GET", "/Ldap/Configuration", None).await;
    assert!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
        "{status}"
    );
}

#[tokio::test]
async fn configuration_round_trips_in_pascal_case() {
    let ldap = Arc::new(FakeLdap::default());
    let (status, json) = call(wired(&ldap), "GET", "/Ldap/Configuration", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["Enabled"], false);
    assert_eq!(json["LdapPort"], 389);

    let mut sent = json.clone();
    sent["Enabled"] = Value::Bool(true);
    sent["LdapServer"] = Value::String("ldap.example.org".to_owned());
    let (status, _) = call(wired(&ldap), "POST", "/Ldap/Configuration", Some(sent)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let saved = ldap.config.lock().expect("lock").clone();
    assert!(saved.enabled);
    assert_eq!(saved.ldap_server, "ldap.example.org");
}

#[tokio::test]
async fn tests_answer_with_the_plugins_shapes() {
    let ldap = Arc::new(FakeLdap::default());
    let (status, json) = call(
        wired(&ldap),
        "POST",
        "/Ldap/TestServerBind",
        Some(serde_json::json!({"LdapServer": "h", "LdapPort": 389, "LdapBindUser": "cn=svc"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["Connect"], "Success");
    assert_eq!(json["Bind"], "cn=svc");
    assert!(json["Error"].is_null());

    let (status, json) = call(
        wired(&ldap),
        "POST",
        "/Ldap/TestLdapFilters",
        Some(serde_json::json!({"LdapSearchFilter": "(uid=*)", "LdapAdminFilter": "_disabled_"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json,
        serde_json::json!({"Users": 2, "Admins": 1, "IsSubset": true})
    );

    let (status, json) = call(
        wired(&ldap),
        "POST",
        "/Ldap/TestLdapFilters",
        Some(serde_json::json!({"LdapSearchFilter": "(uid=*"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["Message"], "User Filter: filter parse error");

    let (status, json) = call(
        wired(&ldap),
        "POST",
        "/Ldap/LdapUserSearch",
        Some(serde_json::json!({"LdapSearchAttributes": "uid", "TestSearchUsername": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        json["Message"],
        "Found no LDAP users matching provided username."
    );
}
