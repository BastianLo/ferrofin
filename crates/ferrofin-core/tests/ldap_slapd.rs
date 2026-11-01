//! The LDAP provider end to end, against a real OpenLDAP `slapd`.
//!
//! Each test starts its own `slapd` on a free local port over a throwaway
//! `mdb` database seeded with two people, and drives the provider through the
//! real [`FerrofinUserManager`] login path. The suite skips itself unless
//! `FERROFIN_LDAP_TESTS` is set *and* `slapd`/`slapadd` are installed, so
//! CI without OpenLDAP stays green.
//!
//! Run with (Debian/Ubuntu: `apt-get install slapd`):
//! `FERROFIN_LDAP_TESTS=1 cargo test -p ferrofin-core --test ldap_slapd`

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ferrofin_core::FerrofinUserManager;
use ferrofin_core::ldap::{LDAP_AUTH_PROVIDER_ID, LdapAuthenticationProvider, LdapConfigStore};
use ferrofin_db::Database;
use ferrofin_model::ldap::{LdapConfiguration, UserFilterInfo, UserSearchAttributes};
use ferrofin_model::secret::Secret;
use ferrofin_traits::error::ServiceError;
use ferrofin_traits::library::UserManager;
use ferrofin_traits::security::{AuthenticationManager, LdapManager};
use uuid::Uuid;

const BASE: &str = "dc=example,dc=org";
const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
const ADMIN_PW: &str = "secret";

/// A tiny red JPEG-ish payload: the provider stores whatever bytes LDAP holds.
const PHOTO: &[u8] = &[
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0xff, 0xd9,
];

const SEED: &str = "dn: dc=example,dc=org
objectClass: dcObject
objectClass: organization
o: Example
dc: example

dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Liddell
mail: alice@example.org
employeeType: admin
userPassword: alicepw

dn: uid=bob,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Builder
mail: bob@example.org
userPassword: bobpw
";

fn find(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

fn which(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .chain([PathBuf::from("/usr/sbin"), PathBuf::from("/usr/local/sbin")])
        .map(|dir| dir.join(binary))
        .find(|p| p.is_file())
}

/// A running `slapd`, killed on drop.
struct Slapd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Slapd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts a seeded `slapd`, or `None` (with a skip line) when the suite is off.
fn slapd() -> Option<Slapd> {
    if std::env::var_os("FERROFIN_LDAP_TESTS").is_none() {
        eprintln!("skipping: set FERROFIN_LDAP_TESTS=1 to run the slapd suite");
        return None;
    }
    let (Some(slapd), Some(slapadd)) = (which("slapd"), which("slapadd")) else {
        eprintln!("skipping: slapd/slapadd not installed");
        return None;
    };
    let schema = find(&["/etc/ldap/schema", "/etc/openldap/schema"])
        .expect("FERROFIN_LDAP_TESTS is set but no OpenLDAP schema directory was found");
    let modules = find(&[
        "/usr/lib/ldap",
        "/usr/lib/openldap",
        "/usr/libexec/openldap",
    ]);
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("db");
    std::fs::create_dir_all(&db).expect("db dir");
    let mut lines: Vec<String> = ["core", "cosine", "nis", "inetorgperson"]
        .iter()
        .map(|s| format!("include {}/{s}.schema", schema.display()))
        .collect();
    if let Some(modules) = modules {
        lines.push(format!("modulepath {}", modules.display()));
        lines.push("moduleload back_mdb".to_owned());
    }
    lines.extend([
        format!("pidfile {}", dir.path().join("slapd.pid").display()),
        "database mdb".to_owned(),
        "maxsize 10485760".to_owned(),
        format!("suffix \"{BASE}\""),
        format!("rootdn \"{ADMIN_DN}\""),
        format!("rootpw {ADMIN_PW}"),
        format!("directory {}", db.display()),
        "access to attrs=userPassword by self write by anonymous auth by * none".to_owned(),
        "access to * by * read".to_owned(),
    ]);
    let conf = lines.join("\n") + "\n";
    let conf_path = dir.path().join("slapd.conf");
    std::fs::write(&conf_path, conf).expect("conf");
    let seed = dir.path().join("seed.ldif");
    std::fs::write(&seed, SEED).expect("seed");
    let status = Command::new(slapadd)
        .arg("-f")
        .arg(&conf_path)
        .arg("-l")
        .arg(&seed)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("slapadd");
    assert!(status.success(), "slapadd failed");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port();
    let child = Command::new(slapd)
        .arg("-f")
        .arg(&conf_path)
        .arg("-h")
        .arg(format!("ldap://127.0.0.1:{port}/"))
        // Stay in the foreground so the child is the server.
        .args(["-d", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("slapd");
    let server = Slapd {
        child,
        port,
        _dir: dir,
    };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(server);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("slapd did not start listening on {port}");
}

fn config(server: &Slapd) -> LdapConfiguration {
    LdapConfiguration {
        enabled: true,
        ldap_server: "127.0.0.1".to_owned(),
        ldap_port: server.port,
        use_ssl: false,
        ldap_bind_user: ADMIN_DN.to_owned(),
        ldap_bind_password: Secret::new(ADMIN_PW),
        ldap_base_dn: BASE.to_owned(),
        ldap_search_filter: "(objectClass=inetOrgPerson)".to_owned(),
        ldap_admin_filter: "(employeeType=admin)".to_owned(),
        ldap_search_attributes: "uid, mail".to_owned(),
        ldap_username_attribute: "uid".to_owned(),
        ..LdapConfiguration::default()
    }
}

struct Harness {
    ldap: Arc<LdapAuthenticationProvider>,
    users: Arc<dyn UserManager>,
}

async fn harness(config: LdapConfiguration) -> Harness {
    let db = Database::connect_in_memory().await.expect("db");
    db.run_migrations().await.expect("migrations");
    let ldap = Arc::new(LdapAuthenticationProvider::new(Arc::new(
        LdapConfigStore::in_memory(config),
    )));
    let users: Arc<dyn UserManager> = Arc::new(FerrofinUserManager::with_providers(
        db,
        vec![Arc::clone(&ldap) as Arc<dyn AuthenticationManager>],
    ));
    ldap.attach_user_manager(Arc::downgrade(&users));
    // The bootstrap admin, a local (default-provider) user.
    users.initialize().await.expect("init");
    Harness { ldap, users }
}

impl Harness {
    /// One login, bounded so a deadlock fails the test instead of hanging it.
    async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<ferrofin_db::entities::users::UserEntity>, ServiceError> {
        tokio::time::timeout(
            Duration::from_secs(20),
            self.users
                .authenticate_user(username, password, "127.0.0.1", true),
        )
        .await
        .expect("login must not hang")
    }

    async fn is_admin(&self, user_id: &str) -> bool {
        let user = self
            .users
            .get_user_by_id(Uuid::parse_str(user_id).expect("id"))
            .await
            .expect("read")
            .expect("user");
        self.users
            .get_user_dto(&user, None)
            .await
            .expect("dto")
            .policy
            .expect("policy")
            .is_administrator
    }
}

/// Runs `ldapmodify`-style changes as the directory admin.
async fn modify(server: &Slapd, dn: &str, mods: Vec<ldap3::Mod<Vec<u8>>>) {
    let (conn, mut ldap) = ldap3::LdapConnAsync::new(&format!("ldap://127.0.0.1:{}", server.port))
        .await
        .expect("connect");
    tokio::spawn(conn.drive());
    ldap.simple_bind(ADMIN_DN, ADMIN_PW)
        .await
        .expect("bind")
        .success()
        .expect("bound");
    ldap.modify(dn, mods)
        .await
        .expect("modify")
        .success()
        .expect("modified");
    let _ = ldap.unbind().await;
}

async fn can_bind(server: &Slapd, dn: &str, password: &str) -> bool {
    let (conn, mut ldap) = ldap3::LdapConnAsync::new(&format!("ldap://127.0.0.1:{}", server.port))
        .await
        .expect("connect");
    tokio::spawn(conn.drive());
    ldap.simple_bind(dn, password)
        .await
        .is_ok_and(|r| r.success().is_ok())
}

#[tokio::test]
async fn a_directory_user_is_created_linked_and_kept_in_sync() {
    let Some(server) = slapd() else { return };
    let h = harness(config(&server)).await;

    // Any search attribute finds the entry; the username attribute names the user.
    let alice = h
        .login("alice@example.org", "alicepw")
        .await
        .expect("login")
        .expect("authenticated");
    assert_eq!(alice.username, "alice");
    assert_eq!(alice.authentication_provider_id, LDAP_AUTH_PROVIDER_ID);
    assert_eq!(alice.password_reset_provider_id, LDAP_AUTH_PROVIDER_ID);
    assert!(h.is_admin(&alice.id).await, "matches the admin filter");
    let links = h.ldap.get_configuration().await.expect("config").ldap_users;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ldap_uid, "alice");

    let bob = h
        .login("bob", "bobpw")
        .await
        .expect("login")
        .expect("authenticated");
    assert!(!h.is_admin(&bob.id).await);

    // Demoted in the directory → demoted on the next login (the policy save
    // re-enters the user manager under this login's lock).
    modify(
        &server,
        "uid=alice,ou=people,dc=example,dc=org",
        vec![ldap3::Mod::Delete(
            b"employeeType".to_vec(),
            std::collections::HashSet::new(),
        )],
    )
    .await;
    let again = h
        .login("alice", "alicepw")
        .await
        .expect("login")
        .expect("authenticated");
    assert_eq!(again.id, alice.id, "the same user, found through its uid");
    assert!(!h.is_admin(&alice.id).await);

    // A new username attribute renames the linked user.
    let mut c = h.ldap.get_configuration().await.expect("config");
    c.ldap_username_attribute = "cn".to_owned();
    h.ldap.update_configuration(c).await.expect("save");
    let renamed = h
        .login("alice", "alicepw")
        .await
        .expect("login")
        .expect("authenticated");
    assert_eq!(renamed.id, alice.id);
    assert_eq!(renamed.username, "Alice");
}

#[tokio::test]
async fn wrong_and_empty_passwords_fail_and_count() {
    let Some(server) = slapd() else { return };
    let h = harness(config(&server)).await;
    let bob = h
        .login("bob", "bobpw")
        .await
        .expect("login")
        .expect("authenticated");

    assert!(h.login("bob", "nope").await.expect("evaluated").is_none());
    // Novell binds an empty password anonymously; it must never log anyone in.
    assert!(h.login("bob", "").await.expect("evaluated").is_none());
    let row = h
        .users
        .get_user_by_id(Uuid::parse_str(&bob.id).expect("id"))
        .await
        .expect("read")
        .expect("user");
    assert_eq!(row.invalid_login_attempt_count, 2);

    // Unknown to the directory and to the server.
    assert!(matches!(
        h.login("mallory", "x").await,
        Err(ServiceError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn without_create_users_an_unknown_user_is_refused() {
    let Some(server) = slapd() else { return };
    let h = harness(LdapConfiguration {
        create_users_from_ldap: false,
        ..config(&server)
    })
    .await;
    assert!(matches!(
        h.login("bob", "bobpw").await,
        Err(ServiceError::Unauthorized(_))
    ));
    assert!(
        h.users
            .get_user_by_name("bob")
            .await
            .expect("read")
            .is_none()
    );
}

#[tokio::test]
async fn a_local_user_of_the_same_name_is_not_taken_over() {
    let Some(server) = slapd() else { return };
    let h = harness(config(&server)).await;
    let local = h.users.create_user("bob").await.expect("create");
    h.users
        .change_password(Uuid::parse_str(&local.id).expect("id"), "localpw")
        .await
        .expect("password");
    // The local user's provider is the default one: the LDAP password is no key.
    assert!(h.login("bob", "bobpw").await.expect("evaluated").is_none());
    let user = h
        .login("bob", "localpw")
        .await
        .expect("login")
        .expect("authenticated");
    assert_eq!(user.id, local.id);
    assert_ne!(user.authentication_provider_id, LDAP_AUTH_PROVIDER_ID);
}

#[tokio::test]
async fn a_password_change_reaches_the_directory() {
    let Some(server) = slapd() else { return };
    let h = harness(LdapConfiguration {
        allow_pass_change: true,
        ..config(&server)
    })
    .await;
    let bob = h
        .login("bob", "bobpw")
        .await
        .expect("login")
        .expect("authenticated");
    let id = Uuid::parse_str(&bob.id).expect("id");
    h.users.change_password(id, "bobpw2").await.expect("change");
    assert!(can_bind(&server, "uid=bob,ou=people,dc=example,dc=org", "bobpw2").await);
    assert!(h.login("bob", "bobpw2").await.expect("login").is_some());
    // An administrator's reset to an empty password never empties the account.
    assert!(matches!(
        h.users.reset_password(id).await,
        Err(ServiceError::InvalidInput(_))
    ));
    assert!(can_bind(&server, "uid=bob,ou=people,dc=example,dc=org", "bobpw2").await);
}

#[tokio::test]
async fn the_admin_tests_report_like_the_plugin() {
    let Some(server) = slapd() else { return };
    let h = harness(config(&server)).await;
    let c = config(&server);
    let report = h
        .ldap
        .test_server_bind(ferrofin_model::ldap::ServerConnectionInfo {
            ldap_server: c.ldap_server.clone(),
            ldap_port: c.ldap_port,
            ldap_bind_user: c.ldap_bind_user.clone(),
            ldap_bind_password: c.ldap_bind_password.clone(),
            ldap_base_dn: c.ldap_base_dn.clone(),
            ..Default::default()
        })
        .await
        .expect("report");
    assert_eq!(report.connect.as_deref(), Some("Success"));
    assert_eq!(report.bind.as_deref(), Some("Success"));
    assert_eq!(report.base_search.as_deref(), Some("Found 4 Entities"));
    assert_eq!(report.error, None);

    let filters = h
        .ldap
        .test_ldap_filters(UserFilterInfo {
            ldap_search_filter: "(objectClass=inetOrgPerson)".to_owned(),
            ldap_admin_filter: "(employeeType=admin)".to_owned(),
            enable_ldap_admin_filter_member_uid: false,
        })
        .await
        .expect("filters");
    assert_eq!(
        (filters.users, filters.admins, filters.is_subset),
        (2, 1, true)
    );
    assert!(matches!(
        h.ldap
            .test_ldap_filters(UserFilterInfo {
                ldap_search_filter: "(objectClass=inetOrgPerson".to_owned(),
                ..Default::default()
            })
            .await,
        Err(ServiceError::InvalidInput(m)) if m.starts_with("User Filter: ")
    ));
    // Restore a valid search filter (the test saved the broken one).
    h.ldap
        .test_ldap_filters(UserFilterInfo {
            ldap_search_filter: "(objectClass=inetOrgPerson)".to_owned(),
            ldap_admin_filter: "_disabled_".to_owned(),
            enable_ldap_admin_filter_member_uid: false,
        })
        .await
        .expect("filters");
    let found = h
        .ldap
        .ldap_user_search(UserSearchAttributes {
            ldap_search_attributes: "mail".to_owned(),
            test_search_username: "bob@example.org".to_owned(),
        })
        .await
        .expect("search");
    assert_eq!(
        found.located_dn.as_deref(),
        Some("uid=bob,ou=people,dc=example,dc=org")
    );
}

#[tokio::test]
async fn profile_images_follow_the_directory() {
    let Some(server) = slapd() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::connect_in_memory().await.expect("db");
    db.run_migrations().await.expect("migrations");
    let ldap = Arc::new(LdapAuthenticationProvider::new(Arc::new(
        LdapConfigStore::in_memory(LdapConfiguration {
            enable_ldap_profile_image_sync: true,
            remove_images_not_in_ldap: true,
            ..config(&server)
        }),
    )));
    let users: Arc<dyn UserManager> = Arc::new(
        FerrofinUserManager::with_providers(
            db,
            vec![Arc::clone(&ldap) as Arc<dyn AuthenticationManager>],
        )
        .with_profile_image_dir(dir.path()),
    );
    ldap.attach_user_manager(Arc::downgrade(&users));
    let bob_dn = "uid=bob,ou=people,dc=example,dc=org";
    modify(
        &server,
        bob_dn,
        vec![ldap3::Mod::Add(
            b"jpegPhoto".to_vec(),
            std::collections::HashSet::from([PHOTO.to_vec()]),
        )],
    )
    .await;

    // Created with the directory's photo.
    let bob = users
        .authenticate_user("bob", "bobpw", "127.0.0.1", true)
        .await
        .expect("login")
        .expect("authenticated");
    let image = dir.path().join("bob").join("profile.jpg");
    assert_eq!(std::fs::read(&image).expect("image"), PHOTO);
    let id = Uuid::parse_str(&bob.id).expect("id");
    assert!(users.get_profile_image(id).await.expect("row").is_some());
    let hash = ldap.get_configuration().await.expect("config").ldap_users[0]
        .profile_image_hash
        .clone();
    assert!(!hash.is_empty());

    // Removed from the directory → removed by the sync.
    modify(
        &server,
        bob_dn,
        vec![ldap3::Mod::Delete(
            b"jpegPhoto".to_vec(),
            std::collections::HashSet::new(),
        )],
    )
    .await;
    ldap.sync_profile_images().await.expect("sync");
    assert!(users.get_profile_image(id).await.expect("row").is_none());
    assert!(!image.exists());
    assert_eq!(
        ldap.get_configuration().await.expect("config").ldap_users[0].profile_image_hash,
        ""
    );

    // Back again → restored by the sync.
    modify(
        &server,
        bob_dn,
        vec![ldap3::Mod::Add(
            b"jpegPhoto".to_vec(),
            std::collections::HashSet::from([PHOTO.to_vec()]),
        )],
    )
    .await;
    ldap.sync_profile_images().await.expect("sync");
    assert_eq!(std::fs::read(&image).expect("image"), PHOTO);
    assert_eq!(
        ldap.get_configuration().await.expect("config").ldap_users[0].profile_image_hash,
        hash
    );
}
