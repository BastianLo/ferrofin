# LDAP authentication

Ferrofin authenticates users against an LDAP directory (OpenLDAP, 389 DS, FreeIPA,
Active Directory, …) with a **core authentication provider** — a port of Jellyfin's
[`jellyfin-plugin-ldapauth`](https://github.com/jellyfin/jellyfin-plugin-ldapauth).
Authentication providers are security-critical core surface, so this is compiled into
the server, never a WASM plugin ([EXTENSIONS.md](EXTENSIONS.md#non-goals-for-the-wasm-tier)).

The provider keeps the plugin's name (`LDAP-Authentication`), id
(`Jellyfin.Plugin.LDAP_Auth.LdapAuthenticationProviderPlugin`), settings and behaviour,
so clients see exactly what a Jellyfin server with the plugin shows them, and users an
adopted Jellyfin database linked to the plugin keep logging in.

## How a login works

As in the plugin:

1. The server binds as the **bind user** and searches below the **base DN** for the
   entry matching the **search filter** AND any **search attribute** equal to the entered
   name (`(&<filter>(|(uid=<name>)(mail=<name>)…))`). A search filter that contains
   `{username}` is used as written instead, with the name substituted. The name is
   escaped (RFC 4515), so it cannot change the filter.
2. The Jellyfin user is found through the stored link to the entry's **uid attribute**,
   else by the entry's **username attribute** among the users LDAP owns. A local user who
   happens to have the same name is never taken over: users keep the provider they have.
3. The server binds as the entry's DN with the entered password. An empty password never
   logs anyone in (LDAP would treat it as an anonymous bind).
4. With an **administrator filter** set, the user is an administrator exactly when the
   filter matches their entry (or, with `EnableLdapAdminFilterMemberUid`, when it matches
   anything — for `memberUid` groups).
5. A missing user is created (`CreateUsersFromLdap`, on by default) with the library
   access the configuration grants; an existing one is renamed when its username attribute
   changed and gets its administrator flag brought in line with the directory.

Failed logins count towards the lockout like any other. Local users (the default
provider) are unaffected by LDAP being on, off, or unreachable.

## Configuring it

**In the dashboard:** Dashboard → **LDAP** (in the drawer's plugin section, with a key
icon). The page is the plugin's settings page, ported: tick **Enable LDAP
authentication**, fill in the server, use the three *Save and Test* buttons, then **Save**.
It is served as a core page (no plugin is installed) through jellyfin-web's
configuration-page mechanism, so it needs no change to jellyfin-web.

The configuration lives in `{config}/ldap.json` (written with `0600` permissions: it
holds the bind password). LDAP is **off** until `Enabled` is `true`. The fields and their
defaults are the plugin's:

| Field | Default | Meaning |
|---|---|---|
| `Enabled` | `false` | Ferrofin's switch (the plugin was on while installed) |
| `LdapServer`, `LdapPort` | `ldap-server.contoso.com`, `389` | the directory |
| `UseSsl` / `UseStartTls` | `true` / `false` | `ldaps://`, or StartTLS on a plain connection |
| `SkipSslVerify` | `false` | accept any server certificate |
| `LdapRootCaPath` | — | PEM CA bundle replacing the system roots |
| `LdapClientCertPath`, `LdapClientKeyPath` | — | PEM client certificate and key |
| `LdapBindUser`, `LdapBindPassword` | — | the account searches run as; empty binds anonymously |
| `LdapBaseDn` | — | where user searches start |
| `LdapSearchFilter` | `(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)` | who may log in |
| `LdapSearchAttributes` | `uid, cn, mail, displayName` | what the entered name is matched against |
| `LdapUidAttribute` | `uid` | the entry's stable identity (`entryUUID`, `objectGUID`, …) |
| `LdapUsernameAttribute` | `cn` | becomes the Jellyfin username |
| `LdapAdminBaseDn`, `LdapAdminFilter` | —, `(enabledService=JellyfinAdministrator)` | administrator mapping; empty or `_disabled_` turns it off |
| `EnableLdapAdminFilterMemberUid` | `false` | see step 4 above |
| `CreateUsersFromLdap` | `true` | create missing users |
| `EnableAllFolders`, `EnabledFolders` | `false`, `[]` | library access of created users |
| `AllowPassChange`, `LdapPasswordAttribute` | `false`, `userPassword` | password changes (below) |
| `PasswordResetUrl` | — | where "forgot password" sends LDAP users |
| `EnableLdapProfileImageSync`, `LdapProfileImageAttribute`, `LdapProfileImageFormat`, `RemoveImagesNotInLdap` | `false`, `jpegphoto`, `Default`, `false` | profile images |
| `LdapUsers` | `[]` | the uid ↔ user links the provider maintains |

Administrators can also manage it over HTTP (every route needs an administrator; they are the
plugin's `LdapController` plus the configuration):

| Route | Does |
|---|---|
| `GET /Ldap/Configuration` | the configuration |
| `POST /Ldap/Configuration` | replace it (send the whole document, as read) |
| `POST /Ldap/TestServerBind` | save the connection settings, report connect → StartTLS → bind → base search |
| `POST /Ldap/TestLdapFilters` | save the filters, count the users and administrators they match (`400` for a bad filter) |
| `POST /Ldap/LdapUserSearch` | save the search attributes, show the DN a test name resolves to |

The test routes also answer under the plugin's lower-case `/ldap/…` spelling.

Like the plugin, each test **saves** the settings it was sent before it runs. A failed
connect or bind answers `401`, a malformed filter `400`, both with `{"Message": "…"}`.

```bash
TOKEN=…   # an administrator's access token
AUTH="Authorization: MediaBrowser Token=\"$TOKEN\", Client=\"curl\", Device=\"curl\", DeviceId=\"curl\", Version=\"1\""
curl -s localhost:8096/Ldap/Configuration -H "$AUTH" > ldap.json
# edit ldap.json: "Enabled": true, server, bind user, base DN, filters …
curl -s -X POST localhost:8096/Ldap/Configuration -H "$AUTH" \
     -H 'Content-Type: application/json' --data @ldap.json
```

Changes apply to the next login; no restart is needed. A hand edit of `ldap.json` is read
at the next start.

## Coming from Jellyfin

When `{config}/ldap.json` does not exist and the Jellyfin plugin's
`{data}/plugins/configurations/LDAP-Auth.xml` does — a Jellyfin data directory being
adopted — Ferrofin imports it once at boot, **with LDAP switched on**, links included, and
logs that it did. The XML is never modified. From then on `ldap.json` is the configuration.
(Database adoption itself is one-way; see [UPGRADING.md](UPGRADING.md).)

## Passwords

- **Changing a password** (`POST /Users/{id}/Password`) writes it to the directory when
  `AllowPassChange` is on: through the Password Modify extended operation (RFC 3062) when
  the server offers it, else by replacing `LdapPasswordAttribute`. The bind user needs the
  right to do so. With `AllowPassChange` off the change is refused.
- **An administrator's "reset password"** (to an empty password) is refused for LDAP
  users. This is the one deliberate divergence from the plugin, which would hand the
  directory an empty password.
- **"Forgot password"** for an LDAP user returns the `PasswordResetUrl` with `$userId` and
  `$userName` filled in (as the plugin's password-reset provider does), instead of writing
  a PIN file; without a URL it fails.

## Profile images

With `EnableLdapProfileImageSync`, a user created from LDAP gets the entry's image, and the
scheduled task **LDAP - Synchronize profile images** (Application, every 24 h) updates every
linked user's image when it changed in the directory, and removes it when the directory has
none and `RemoveImagesNotInLdap` is on. `LdapProfileImageFormat` `Default` detects raw bytes,
Base64 or an `http(s)` URL (downloads are capped at 16 MiB). An image that cannot be read
never blocks the login it belongs to. The task is listed while LDAP is on.

## Referrals and timeouts

Searches follow referrals (search continuations and referral results), binding to the
referred server as the bind user, up to ten hops — Novell's referral handling in the
plugin. A referral that cannot be followed is logged and skipped. Connecting may take 15 s
and each LDAP operation 30 s, so a stalled directory fails a login instead of holding it.

## Testing

`crates/ferrofin-core/tests/ldap_slapd.rs` runs the whole flow against a real OpenLDAP
`slapd` it starts per test. It needs `slapd`/`slapadd` (Debian/Ubuntu: `apt-get install
slapd`) and is off unless asked for:

```bash
FERROFIN_LDAP_TESTS=1 cargo test -p ferrofin-core --test ldap_slapd
```

