//! `LdapController` — administration of the core LDAP authentication provider.
//!
//! Port of `jellyfin-plugin-ldapauth`'s `Api/LdapController.cs`
//! (`[Route("[controller]")]`, `[Authorize(Policy = Policies.RequiresElevation)]`),
//! plus the provider's configuration, which upstream is the plugin configuration
//! (`/Plugins/{id}/Configuration`) and in Ferrofin — where LDAP is core, not a
//! plugin (`docs/EXTENSIONS.md`) — has its own pair of routes:
//! - `GET  /Ldap/Configuration` — the configuration ([`LdapConfiguration`]).
//! - `POST /Ldap/Configuration` — replace it.
//! - `POST /Ldap/TestServerBind` — save the connection settings and test them.
//! - `POST /Ldap/TestLdapFilters` — save the filters and count their matches.
//! - `POST /Ldap/LdapUserSearch` — save the search attributes and locate a user.
//!
//! The dashboard gets an "LDAP" entry in its admin drawer
//! ([`configuration_page_info`]) whose page ([`CONFIG_PAGE_HTML`], the plugin's
//! settings page ported to these routes) is served by `handlers::dashboard`.
//!
//! These routes are not in the vendored Jellyfin contract (the plugin's routes
//! never were), so like `/Plugins/{id}/web/*` they are registered but not listed
//! in `REAL_ROUTES`. Every route requires an administrator. A failed bind answers
//! `401` and a bad filter `400`, each with the plugin's `{"Message": …}` body.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ferrofin_model::ldap::{
    LdapConfiguration, LdapFilterResponse, LdapTestErrorResponse, ServerConnectionInfo,
    ServerTestResponse, UserFilterInfo, UserSearchAttributes, UserSearchResponse,
};
use ferrofin_traits::error::ServiceError;
use ferrofin_traits::security::LdapManager;

use crate::auth::RequireAdmin;
use crate::error::ApiError;
use crate::extract::JsonBody;
use crate::state::AppState;

/// The name the LDAP settings page is fetched by
/// (`/web/configurationpage?name=LDAP`).
pub const CONFIG_PAGE_NAME: &str = "LDAP";

/// The page's id: the upstream plugin's GUID (`LdapPlugin.Id`). jellyfin-web
/// keys the dashboard drawer entry on it; no plugin with it is installed, so the
/// plugins list never pairs it with one.
const CONFIG_PAGE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x958a_ad66_3784_4d2a_b89a_a7b6_fab6_e25c);

/// The LDAP settings page: a port of the plugin's `configPage.html` over
/// `/Ldap/Configuration` and the test routes.
pub const CONFIG_PAGE_HTML: &str = include_str!("ldap_config_page.html");

/// The dashboard entry for the LDAP settings page, in the admin drawer.
#[must_use]
pub fn configuration_page_info() -> ferrofin_model::plugins::ConfigurationPageInfo {
    ferrofin_model::plugins::ConfigurationPageInfo {
        name: CONFIG_PAGE_NAME.to_owned(),
        enable_in_main_menu: true,
        menu_section: Some("server".to_owned()),
        menu_icon: Some("vpn_key".to_owned()),
        display_name: Some("LDAP".to_owned()),
        plugin_id: Some(CONFIG_PAGE_ID),
    }
}

/// The wired LDAP manager, or `503` when the composition root wired none.
fn ldap(state: &AppState) -> Result<&dyn LdapManager, ApiError> {
    state
        .ldap
        .as_deref()
        .ok_or_else(|| ApiError::ServiceUnavailable("LDAP is not available".to_owned()))
}

/// The plugin's error answer for a test: `401` for a failed connect or bind,
/// `400` for a bad filter, each with `{"Message": …}`; anything else as usual.
fn test_error(error: ServiceError) -> Response {
    let status = match &error {
        ServiceError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        ServiceError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        _ => return ApiError::from(error).into_response(),
    };
    let message = match error {
        ServiceError::Unauthorized(m) | ServiceError::InvalidInput(m) => m,
        _ => String::new(),
    };
    (status, Json(LdapTestErrorResponse { message })).into_response()
}

/// `GET /Ldap/Configuration` — the LDAP configuration.
#[utoipa::path(
    get,
    path = "/Ldap/Configuration",
    responses((status = 200, description = "LDAP configuration", body = LdapConfiguration)),
    tag = "ferrofin"
)]
async fn get_configuration(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
) -> Result<Json<LdapConfiguration>, ApiError> {
    Ok(Json(ldap(&state)?.get_configuration().await?))
}

/// `POST /Ldap/Configuration` — replaces the LDAP configuration.
#[utoipa::path(
    post,
    path = "/Ldap/Configuration",
    request_body = LdapConfiguration,
    responses((status = 204, description = "Configuration saved")),
    tag = "ferrofin"
)]
async fn update_configuration(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    JsonBody(config): JsonBody<LdapConfiguration>,
) -> Result<StatusCode, ApiError> {
    ldap(&state)?.update_configuration(config).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /Ldap/TestServerBind` — saves the connection settings, then reports
/// connect, StartTLS, bind and base search step by step.
#[utoipa::path(
    post,
    path = "/Ldap/TestServerBind",
    request_body = ServerConnectionInfo,
    responses((status = 200, description = "Test steps", body = ServerTestResponse)),
    tag = "ferrofin"
)]
async fn test_server_bind(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    JsonBody(body): JsonBody<ServerConnectionInfo>,
) -> Result<Json<ServerTestResponse>, ApiError> {
    Ok(Json(ldap(&state)?.test_server_bind(body).await?))
}

/// `POST /Ldap/TestLdapFilters` — saves the filters, then counts the users and
/// administrators they match.
#[utoipa::path(
    post,
    path = "/Ldap/TestLdapFilters",
    request_body = UserFilterInfo,
    responses(
        (status = 200, description = "Filter matches", body = LdapFilterResponse),
        (status = 400, description = "A filter is invalid", body = LdapTestErrorResponse),
        (status = 401, description = "Could not bind", body = LdapTestErrorResponse)
    ),
    tag = "ferrofin"
)]
async fn test_ldap_filters(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    JsonBody(body): JsonBody<UserFilterInfo>,
) -> Result<Response, ApiError> {
    Ok(match ldap(&state)?.test_ldap_filters(body).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => test_error(error),
    })
}

/// `POST /Ldap/LdapUserSearch` — saves the search attributes, then locates the
/// test username's entry.
#[utoipa::path(
    post,
    path = "/Ldap/LdapUserSearch",
    request_body = UserSearchAttributes,
    responses(
        (status = 200, description = "Located entry", body = UserSearchResponse),
        (status = 401, description = "Could not bind or find the user", body = LdapTestErrorResponse)
    ),
    tag = "ferrofin"
)]
async fn ldap_user_search(
    State(state): State<AppState>,
    RequireAdmin(_auth): RequireAdmin,
    JsonBody(body): JsonBody<UserSearchAttributes>,
) -> Result<Response, ApiError> {
    Ok(match ldap(&state)?.ldap_user_search(body).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => test_error(error),
    })
}

/// Registers the LDAP routes onto `router`.
pub fn register(router: Router<AppState>) -> Router<AppState> {
    router
        .route(
            "/Ldap/Configuration",
            get(get_configuration).post(update_configuration),
        )
        .route("/Ldap/TestServerBind", post(test_server_bind))
        .route("/Ldap/TestLdapFilters", post(test_ldap_filters))
        .route("/Ldap/LdapUserSearch", post(ldap_user_search))
        // ASP.NET routing is case-insensitive and the plugin's page (and any
        // script written against it) posts to `ldap/…`; axum's is not.
        .route("/ldap/TestServerBind", post(test_server_bind))
        .route("/ldap/TestLdapFilters", post(test_ldap_filters))
        .route("/ldap/LdapUserSearch", post(ldap_user_search))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[tokio::test]
    async fn test_errors_carry_the_plugins_message_body() {
        let (status, json) = body(test_error(ServiceError::Unauthorized(
            "Failed to Connect or Bind to server.".to_owned(),
        )))
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["Message"], "Failed to Connect or Bind to server.");

        let (status, json) = body(test_error(ServiceError::InvalidInput(
            "User Filter: filter parse error".to_owned(),
        )))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["Message"], "User Filter: filter parse error");

        let (status, _) = body(test_error(ServiceError::backend("boom"))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
