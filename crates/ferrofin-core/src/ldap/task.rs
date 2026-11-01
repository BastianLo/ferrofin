//! "LDAP - Synchronize profile images" — port of the plugin's
//! `LdapProfileImageSyncTask`.

use std::sync::Arc;

use async_trait::async_trait;
use ferrofin_model::tasks::TaskTriggerInfo;
use ferrofin_traits::error::ServiceError;
use ferrofin_traits::security::LdapManager;

use super::LdapConfigStore;
use crate::scheduled_tasks::{ScheduledTask, TaskProgress, interval_hours};

/// Synchronises every LDAP-linked user's profile image from the directory, every
/// 24 hours (the plugin's default trigger).
///
/// Upstream the task exists while the plugin is installed. A core provider is
/// always compiled in, so the task is registered always and reports itself
/// hidden (as an `IConfigurableScheduledTask`) while LDAP is switched off —
/// the dashboard then lists it exactly when upstream would.
pub struct LdapProfileImageSyncTask {
    ldap: Arc<dyn LdapManager>,
    store: Arc<LdapConfigStore>,
}

impl LdapProfileImageSyncTask {
    /// Builds the task over the provider and its configuration.
    #[must_use]
    pub fn new(ldap: Arc<dyn LdapManager>, store: Arc<LdapConfigStore>) -> Self {
        Self { ldap, store }
    }
}

#[allow(clippy::unnecessary_literal_bound)]
#[async_trait]
impl ScheduledTask for LdapProfileImageSyncTask {
    fn key(&self) -> &str {
        "LdapProfileImageSync"
    }
    fn name(&self) -> &str {
        "LDAP - Synchronize profile images"
    }
    fn description(&self) -> &str {
        "Synchronizes user profile images from LDAP."
    }
    fn category(&self) -> &str {
        "Application"
    }
    fn is_configurable(&self) -> bool {
        true
    }
    fn is_hidden(&self) -> bool {
        !self.store.is_enabled()
    }
    fn default_triggers(&self) -> Vec<TaskTriggerInfo> {
        vec![interval_hours(24)]
    }
    async fn execute(&self, progress: &TaskProgress) -> Result<(), ServiceError> {
        progress.report(0.0);
        self.ldap.sync_profile_images().await?;
        progress.report(100.0);
        Ok(())
    }
}
