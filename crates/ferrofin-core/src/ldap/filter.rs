//! The pure string logic of the LDAP provider: filter escaping and assembly,
//! reset-URL templating and profile-image format detection.
//!
//! Port of `Helpers/LdapUtils.cs` and the filter assembly in
//! `LdapAuthenticationProviderPlugin.LocateLdapUser` / `Authenticate`.

use base64::Engine as _;
use ferrofin_model::ldap::ProfileImageFormat;

/// The placeholder a search or administrator filter carries for the username.
const USERNAME_PLACEHOLDER: &str = "{username}";

/// Escapes the characters RFC 4515 reserves in a filter value (port of
/// `LdapUtils.SanitizeFilter`).
#[must_use]
pub fn sanitize_filter(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            other => out.push(other),
        }
    }
    out
}

/// Replaces every occurrence of the ASCII `needle` in `haystack`, ignoring ASCII
/// case (`string.Replace(…, StringComparison.OrdinalIgnoreCase)` for the ASCII
/// placeholders the plugin uses).
#[must_use]
pub fn replace_ignore_ascii_case(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_owned();
    }
    let lower = haystack.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0;
    // ASCII lower-casing keeps every byte offset, so offsets found in `lower`
    // are valid char boundaries in `haystack`.
    for (start, _) in lower.match_indices(&needle) {
        out.push_str(&haystack[last..start]);
        out.push_str(replacement);
        last = start + needle.len();
    }
    out.push_str(&haystack[last..]);
    out
}

/// Whether `haystack` contains the ASCII `needle`, ignoring ASCII case.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// The configured username attributes: spaces removed, split on commas
/// (`LdapSearchAttributes.Replace(" ", "").Split(',')`).
#[must_use]
pub fn search_attributes(configured: &str) -> Vec<String> {
    configured
        .replace(' ', "")
        .split(',')
        .map(str::to_owned)
        .collect()
}

/// The filter that locates `username` (port of the `LocateLdapUser` assembly).
///
/// A search filter with a `{username}` placeholder is used as is, with the
/// escaped username substituted; any other is AND-ed with an OR of every search
/// attribute equal to the username.
#[must_use]
pub fn user_search_filter(search_filter: &str, attributes: &str, username: &str) -> String {
    let sanitized = sanitize_filter(username);
    if contains_ignore_ascii_case(search_filter, USERNAME_PLACEHOLDER) {
        return replace_ignore_ascii_case(search_filter, USERNAME_PLACEHOLDER, &sanitized);
    }
    let mut filter = String::from("(&");
    filter.push_str(search_filter);
    filter.push_str("(|");
    for attribute in search_attributes(attributes) {
        filter.push('(');
        filter.push_str(&attribute);
        filter.push('=');
        filter.push_str(&sanitized);
        filter.push(')');
    }
    filter.push_str("))");
    filter
}

/// The administrator filter with the escaped username substituted for
/// `{username}`.
#[must_use]
pub fn admin_search_filter(admin_filter: &str, username: &str) -> String {
    replace_ignore_ascii_case(
        admin_filter,
        USERNAME_PLACEHOLDER,
        &sanitize_filter(username),
    )
}

/// The password reset URL for a user (port of `StartForgotPasswordProcess`):
/// `$userId` becomes the user's id, `$userName` the entered username in lower
/// case.
#[must_use]
pub fn password_reset_url(template: &str, user_id: &str, entered_username: &str) -> String {
    let url = replace_ignore_ascii_case(template, "$userId", user_id);
    replace_ignore_ascii_case(&url, "$userName", &entered_username.to_lowercase())
}

/// Detects how a text attribute value encodes an image (port of
/// `LdapUtils.TryDetermineAttributeFormat`): a control character means raw
/// bytes, valid Base64 means Base64, an absolute `http(s)` URL means a download.
///
/// # Errors
/// The reason, when the value is none of the three.
pub fn detect_profile_image_format(value: &str) -> Result<ProfileImageFormat, String> {
    if value
        .chars()
        .any(|c| c == '\u{7f}' || (c < '\u{20}' && !matches!(c, '\n' | '\r' | '\t')))
    {
        return Ok(ProfileImageFormat::Binary);
    }
    if is_valid_base64(value) {
        return Ok(ProfileImageFormat::Base64);
    }
    match reqwest::Url::parse(value) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => Ok(ProfileImageFormat::Url),
        Ok(url) => Err(format!(
            "ProfileImage Format detection failed. Attribute value was a valid URI but had an invalid Scheme, expected one of [http, https]. Got: {}",
            url.scheme()
        )),
        Err(_) => Err(format!(
            "ProfileImage Format detection failed. Expected absolute URI but attribute value appears to be a relative path. Got: {value}"
        )),
    }
}

/// `System.Buffers.Text.Base64.IsValid`: standard alphabet, whitespace ignored,
/// a length that is a multiple of four and at most two trailing `=`.
fn is_valid_base64(value: &str) -> bool {
    let compact: Vec<u8> = value
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    if !compact.len().is_multiple_of(4) {
        return false;
    }
    let padding = compact.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return false;
    }
    compact[..compact.len() - padding]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

/// Decodes a Base64 attribute value, ignoring whitespace
/// (`Convert.FromBase64String`).
///
/// # Errors
/// The decoder's message for invalid input.
pub fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|e| e.to_string())
}

/// The hash recorded for a synchronised profile image:
/// `Convert.ToBase64String(MD5.HashData(image))`.
#[must_use]
pub fn profile_image_hash(image: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(ferrofin_common::extensions::md5_digest(image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("alice", "alice")]
    #[case("a*b", "a\\2ab")]
    #[case("(x)", "\\28x\\29")]
    #[case("back\\slash", "back\\5cslash")]
    #[case("nul\0", "nul\\00")]
    #[case("*)(uid=*", "\\2a\\29\\28uid=\\2a")]
    fn sanitize_filter_escapes_reserved_characters(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(sanitize_filter(input), expected);
    }

    #[test]
    fn search_filter_without_placeholder_ors_every_attribute() {
        assert_eq!(
            user_search_filter("(memberOf=cn=media)", "uid, cn , mail", "bob"),
            "(&(memberOf=cn=media)(|(uid=bob)(cn=bob)(mail=bob)))"
        );
    }

    #[test]
    fn search_filter_with_placeholder_is_used_verbatim() {
        assert_eq!(
            user_search_filter("(&(objectClass=person)(UID={USERNAME}))", "uid", "a*"),
            "(&(objectClass=person)(UID=a\\2a))"
        );
    }

    #[test]
    fn injection_through_the_username_is_escaped() {
        let filter = user_search_filter("(objectClass=person)", "uid", "*)(uid=*");
        assert_eq!(
            filter,
            "(&(objectClass=person)(|(uid=\\2a\\29\\28uid=\\2a)))"
        );
        assert!(ldap3::parse_filter(&filter).is_ok());
    }

    #[test]
    fn admin_filter_substitutes_the_username() {
        assert_eq!(
            admin_search_filter("(&(cn=admins)(memberUid={Username}))", "bo(b"),
            "(&(cn=admins)(memberUid=bo\\28b))"
        );
        assert_eq!(admin_search_filter("(cn=admins)", "bob"), "(cn=admins)");
    }

    #[test]
    fn reset_url_fills_both_placeholders() {
        assert_eq!(
            password_reset_url(
                "https://id.example/reset?u=$USERNAME&id=$userid",
                "6f1c",
                "Alice"
            ),
            "https://id.example/reset?u=alice&id=6f1c"
        );
    }

    #[test]
    fn replace_keeps_non_ascii_text_intact() {
        assert_eq!(
            replace_ignore_ascii_case("Grüße {USERNAME} ✓", "{username}", "jörg"),
            "Grüße jörg ✓"
        );
    }

    #[rstest]
    #[case("\u{1}\u{2}JFIF", Ok(ProfileImageFormat::Binary))]
    #[case("aGVsbG8=", Ok(ProfileImageFormat::Base64))]
    #[case("aGVs\nbG8=", Ok(ProfileImageFormat::Base64))]
    #[case("https://img.example/a.jpg", Ok(ProfileImageFormat::Url))]
    #[case("http://img.example/a.jpg", Ok(ProfileImageFormat::Url))]
    fn profile_image_format_detection(
        #[case] value: &str,
        #[case] expected: Result<ProfileImageFormat, String>,
    ) {
        assert_eq!(detect_profile_image_format(value), expected);
    }

    #[test]
    fn profile_image_format_detection_rejects_other_values() {
        assert!(detect_profile_image_format("ftp://img.example/a.jpg").is_err());
        // Whitespace is ignored, so "not base64 nor a url" *is* Base64 to .NET too.
        assert!(detect_profile_image_format("no url!").is_err());
        assert!(!is_valid_base64("abc"));
        assert!(!is_valid_base64("ab==="));
    }

    #[test]
    fn base64_round_trip_and_hash() {
        assert_eq!(decode_base64("aGVs\r\nbG8=").as_deref(), Ok(&b"hello"[..]));
        assert!(decode_base64("@@@@").is_err());
        // MD5("hello") = 5d41402abc4b2a76b9719d911017c592.
        assert_eq!(profile_image_hash(b"hello"), "XUFAKrxLKna5cZ2REBfFkg==");
    }
}
