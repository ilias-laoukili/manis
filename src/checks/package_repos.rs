//! `package_repos` check primitive validating APT (`.list` and DEB822 `.sources`) and
//! YUM/DNF repository domains and GPG enforcement.
//!
//! APT sources are read as described in `sources.list(5)` and `apt-transport-mirror(1)`:
//! DEB822 values may continue on lines starting with whitespace, boolean options are read like
//! APT's `StringToBool`, and `mirror+file:` sources are resolved through their mirror list inside
//! the audited root.

use crate::checks::{expand_virtual_paths, CheckOutcome};
use crate::rules::schema::PackageReposCheck;
use crate::sys::SystemView;

/// One-line APT source files.
pub const APT_LIST_PATTERNS: &[&str] = &["/etc/apt/sources.list", "/etc/apt/sources.list.d/*.list"];

/// DEB822 APT source files (default format on Ubuntu 24.04 and Debian 12/13).
pub const APT_DEB822_PATTERNS: &[&str] = &["/etc/apt/sources.list.d/*.sources"];

/// YUM/DNF repository files.
pub const YUM_REPO_PATTERNS: &[&str] = &["/etc/yum.repos.d/*.repo"];

/// APT configuration files that can weaken signature verification globally.
pub const APT_CONF_PATTERNS: &[&str] = &["/etc/apt/apt.conf", "/etc/apt/apt.conf.d/*"];

/// YUM/DNF global configuration files.
pub const YUM_GLOBAL_CONF_PATHS: &[&str] = &["/etc/yum.conf", "/etc/dnf/dnf.conf"];

/// APT source options that weaken signature verification when set to a true value
/// (`sources.list(5)`). DEB822 field names are the same words, compared case-insensitively.
const APT_WEAKENING_OPTIONS: &[&str] = &[
    "trusted",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
];

/// APT configuration options that weaken signature verification when set to a true value.
const APT_CONF_WEAKENING_OPTIONS: &[&str] = &[
    "allowunauthenticated",
    "allowinsecurerepositories",
    "allowweakrepositories",
    "allowdowngradetoinsecurerepositories",
];

/// Mirror list extensions that APT decompresses but this primitive does not inspect.
const COMPRESSED_MIRROR_LIST_EXTENSIONS: &[&str] = &[".gz", ".xz", ".bz2", ".lzma", ".lz4", ".zst"];

/// Evaluates package repository trust and GPG signature settings.
pub fn evaluate(spec: &PackageReposCheck, view: &dyn SystemView) -> CheckOutcome {
    let trusted: Vec<String> = spec
        .trusted_domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    let mut scan = Scan {
        view,
        trusted: &trusted,
        check_gpg: spec.check_gpg,
        repo_files_checked: 0,
        urls_checked: 0,
        violations: Vec::new(),
        unreadable: Vec::new(),
    };

    // 1. One-line APT sources (.list)
    for path in scan.expand(APT_LIST_PATTERNS) {
        if let Some(content) = scan.read(&path) {
            scan.repo_files_checked += 1;
            inspect_apt_list(&mut scan, &path, &content);
        }
    }

    // 2. DEB822 APT sources (.sources — Ubuntu 24.04 and Debian 12/13 default)
    for path in scan.expand(APT_DEB822_PATTERNS) {
        if let Some(content) = scan.read(&path) {
            scan.repo_files_checked += 1;
            inspect_deb822_sources(&mut scan, &path, &content);
        }
    }

    // 3. YUM/DNF repos
    for path in scan.expand(YUM_REPO_PATTERNS) {
        if let Some(content) = scan.read(&path) {
            scan.repo_files_checked += 1;
            inspect_yum_repo(&mut scan, &path, &content);
        }
    }

    // 4. Global APT & YUM/DNF GPG settings
    if spec.check_gpg {
        for path in scan.expand(APT_CONF_PATTERNS) {
            if let Some(content) = scan.read(&path) {
                inspect_apt_conf(&path, &content, &mut scan.violations);
            }
        }
        for path in YUM_GLOBAL_CONF_PATHS {
            if let Some(content) = scan.read(path) {
                inspect_yum_global_conf(path, &content, &mut scan.violations);
            }
        }
    }

    scan.into_outcome()
}

/// State shared by the repository file inspectors.
struct Scan<'a> {
    view: &'a dyn SystemView,
    trusted: &'a [String],
    check_gpg: bool,
    repo_files_checked: usize,
    urls_checked: usize,
    violations: Vec<String>,
    unreadable: Vec<String>,
}

impl Scan<'_> {
    /// Expands path patterns, recording directories that cannot be listed.
    fn expand(&mut self, patterns: &[&str]) -> Vec<String> {
        let owned: Vec<String> = patterns.iter().map(ToString::to_string).collect();
        let (files, unreadable) = expand_virtual_paths(self.view, &owned);
        self.unreadable.extend(unreadable);
        files
    }

    /// Reads a file; a missing file is skipped and any other error is recorded as unreadable.
    fn read(&mut self, path: &str) -> Option<String> {
        match self.view.read_to_string(path) {
            Ok(content) => Some(content),
            Err(err) if err.is_not_found() => None,
            Err(err) => {
                self.unreadable.push(format!("{path}: {err}"));
                None
            }
        }
    }

    /// Checks one repository URI; `mirror+file:` URIs are checked through their mirror list.
    fn check_uri(&mut self, origin: &str, kind: &str, uri: &str) {
        if let Some(list_path) = mirror_file_path(uri) {
            self.check_mirror_list(origin, uri, &list_path);
            return;
        }
        self.urls_checked += 1;
        if !is_uri_trusted(uri, self.trusted) {
            self.violations
                .push(format!("{origin}: untrusted {kind} '{uri}'"));
        }
    }

    /// Checks every mirror of an `apt-transport-mirror(1)` list: one URI per line, optional
    /// metadata after a tab, blank lines and `#` lines ignored. A list that cannot be inspected
    /// is recorded as unreadable, so it can never yield `PASS`.
    fn check_mirror_list(&mut self, origin: &str, uri: &str, list_path: &str) {
        if COMPRESSED_MIRROR_LIST_EXTENSIONS
            .iter()
            .any(|ext| list_path.ends_with(ext))
        {
            self.unreadable.push(format!(
                "{list_path}: compressed mirror list not inspected ({uri} in {origin})"
            ));
            return;
        }
        let content = match self.view.read_to_string(list_path) {
            Ok(content) => content,
            Err(err) => {
                self.unreadable.push(format!(
                    "{list_path}: {err} (mirror list for {uri} in {origin})"
                ));
                return;
            }
        };
        let mirrors: Vec<&str> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        if mirrors.is_empty() {
            self.unreadable.push(format!(
                "{list_path}: mirror list has no entries ({uri} in {origin})"
            ));
            return;
        }
        for mirror in mirrors {
            self.urls_checked += 1;
            if !is_uri_trusted(mirror, self.trusted) {
                self.violations.push(format!(
                    "{origin}: untrusted mirror '{mirror}' listed in {list_path}"
                ));
            }
        }
    }

    fn into_outcome(mut self) -> CheckOutcome {
        self.unreadable.sort();
        self.unreadable.dedup();

        let expected = if self.check_gpg {
            "only trusted repository domains and GPG verification enabled"
        } else {
            "only trusted repository domains"
        };

        if !self.violations.is_empty() {
            let actual = format!("{} repository/GPG violation(s)", self.violations.len());
            let mut details = self.violations;
            details.extend(self.unreadable);
            return CheckOutcome::fail(expected, actual, details);
        }

        if self.repo_files_checked == 0 {
            return CheckOutcome::warn(
                expected,
                "no package repository configuration files found",
                if self.unreadable.is_empty() {
                    vec!["neither APT nor YUM/DNF repository files were found".to_string()]
                } else {
                    self.unreadable
                },
            );
        }

        if !self.unreadable.is_empty() {
            return CheckOutcome::warn(
                expected,
                format!(
                    "{} repository URI(s) trusted, but {} path(s) unreadable",
                    self.urls_checked,
                    self.unreadable.len()
                ),
                self.unreadable,
            );
        }

        CheckOutcome::pass(
            expected,
            format!(
                "{} repository URI(s) across {} file(s) trusted with GPG intact",
                self.urls_checked, self.repo_files_checked
            ),
        )
    }
}

fn inspect_apt_list(scan: &mut Scan<'_>, path: &str, content: &str) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let rest = if let Some(r) = line.strip_prefix("deb-src") {
            r
        } else if let Some(r) = line.strip_prefix("deb") {
            r
        } else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let origin = format!("{path}:{}", idx + 1);
        let mut rest = rest.trim_start();
        if let Some(after_open) = rest.strip_prefix('[') {
            if let Some((opts, after_close)) = after_open.split_once(']') {
                if scan.check_gpg && apt_options_weaken_gpg(opts) {
                    scan.violations.push(format!(
                        "{origin}: APT source disables GPG verification ([{opts}])"
                    ));
                }
                rest = after_close.trim_start();
            }
        }
        if let Some(uri) = rest.split_whitespace().next() {
            scan.check_uri(&origin, "repository URI", uri);
        }
    }
}

/// Returns `true` when one-line options (`[key=value ...]`) set a weakening option to true.
fn apt_options_weaken_gpg(opts: &str) -> bool {
    opts.split_whitespace().any(|token| {
        token
            .split_once('=')
            .is_some_and(|(key, value)| is_weakening_option(key) && apt_bool(value) == Some(true))
    })
}

fn is_weakening_option(key: &str) -> bool {
    APT_WEAKENING_OPTIONS
        .iter()
        .any(|option| key.trim().eq_ignore_ascii_case(option))
}

fn inspect_deb822_sources(scan: &mut Scan<'_>, path: &str, content: &str) {
    for stanza in parse_deb822(content) {
        let enabled = stanza
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("Enabled"))
            .map_or(true, |(_, value)| apt_bool(value) != Some(false));
        if !enabled {
            continue;
        }
        for (_, uris) in stanza
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("URIs"))
        {
            for uri in uris.split_whitespace() {
                scan.check_uri(path, "DEB822 repository URI", uri);
            }
        }
        if scan.check_gpg {
            for (key, value) in &stanza {
                if is_weakening_option(key) && apt_bool(value) == Some(true) {
                    scan.violations
                        .push(format!("{path}: DEB822 stanza sets '{key}: {value}'"));
                }
            }
        }
    }
}

/// Splits DEB822 content into stanzas of `(field, value)` pairs.
///
/// Blank lines end a stanza and `#` lines are comments. A line starting with whitespace
/// continues the previous field, because `sources.list(5)` separates values by spaces, tabs and
/// newlines (e.g. several `URIs` lines, or an inline `Signed-By` key block).
fn parse_deb822(content: &str) -> Vec<Vec<(String, String)>> {
    let mut stanzas = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    for raw_line in content.lines() {
        if raw_line.trim().is_empty() {
            if !current.is_empty() {
                stanzas.push(std::mem::take(&mut current));
            }
            continue;
        }
        if raw_line.trim_start().starts_with('#') {
            continue;
        }
        if raw_line.starts_with(char::is_whitespace) {
            if let Some((_, value)) = current.last_mut() {
                value.push(' ');
                value.push_str(raw_line.trim());
            }
            continue;
        }
        if let Some((key, value)) = raw_line.split_once(':') {
            current.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    if !current.is_empty() {
        stanzas.push(current);
    }
    stanzas
}

fn inspect_yum_repo(scan: &mut Scan<'_>, path: &str, content: &str) {
    let mut enabled = true;
    let mut stanza_urls: Vec<String> = Vec::new();
    let mut gpg_disabled = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush_yum_stanza(scan, path, enabled, &mut stanza_urls, &mut gpg_disabled);
            enabled = true;
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            if key.eq_ignore_ascii_case("enabled") {
                enabled = val != "0" && !val.eq_ignore_ascii_case("false");
            } else if key.eq_ignore_ascii_case("baseurl")
                || key.eq_ignore_ascii_case("mirrorlist")
                || key.eq_ignore_ascii_case("metalink")
            {
                stanza_urls.push(val.to_string());
            } else if key.eq_ignore_ascii_case("gpgcheck")
                && (val == "0" || val.eq_ignore_ascii_case("false"))
            {
                gpg_disabled = true;
            }
        }
    }
    flush_yum_stanza(scan, path, enabled, &mut stanza_urls, &mut gpg_disabled);
}

fn flush_yum_stanza(
    scan: &mut Scan<'_>,
    path: &str,
    enabled: bool,
    stanza_urls: &mut Vec<String>,
    gpg_disabled: &mut bool,
) {
    if enabled {
        for uri in stanza_urls.drain(..) {
            scan.check_uri(path, "YUM/DNF repository URI", &uri);
        }
        if scan.check_gpg && *gpg_disabled {
            scan.violations.push(format!(
                "{path}: repository disables GPG check (gpgcheck=0)"
            ));
        }
    } else {
        stanza_urls.clear();
    }
    *gpg_disabled = false;
}

fn inspect_apt_conf(path: &str, content: &str, violations: &mut Vec<String>) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let weakens = APT_CONF_WEAKENING_OPTIONS.iter().any(|option| {
            lower.find(option).is_some_and(|pos| {
                apt_bool(apt_conf_value(&lower[pos + option.len()..])) == Some(true)
            })
        });
        if weakens {
            violations.push(format!(
                "{path}:{}: APT configuration weakens GPG verification ({line})",
                idx + 1
            ));
        }
    }
}

/// Returns the value that follows an APT configuration key: a `"quoted"` string or a bare word.
fn apt_conf_value(after_key: &str) -> &str {
    let rest = after_key.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next().unwrap_or("")
    } else {
        rest.split(|c: char| c == ';' || c.is_whitespace())
            .next()
            .unwrap_or("")
    }
}

/// Reads a boolean like APT's `StringToBool` (`apt-pkg/contrib/strutl.cc`): a whole-string
/// integer `0` or `1` (base detected like `strtol`), or `no`/`false`/`without`/`off`/`disable`
/// and `yes`/`true`/`with`/`on`/`enable`, ignoring case. Returns `None` for any other value.
fn apt_bool(raw: &str) -> Option<bool> {
    let value = raw.trim();
    if let Some(number) = parse_c_integer(value) {
        return match number {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
    }
    match value.to_ascii_lowercase().as_str() {
        "no" | "false" | "without" | "off" | "disable" => Some(false),
        "yes" | "true" | "with" | "on" | "enable" => Some(true),
        _ => None,
    }
}

/// Parses a whole string as a C integer with `strtol` base detection (`0x` hex, leading `0`
/// octal, decimal otherwise) and an optional sign.
fn parse_c_integer(value: &str) -> Option<i64> {
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    let (radix, digits) = if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        (16, hex)
    } else if unsigned.len() > 1 && unsigned.starts_with('0') {
        (8, &unsigned[1..])
    } else {
        (10, unsigned)
    };
    if digits.is_empty() || digits.starts_with(['+', '-']) {
        return None;
    }
    let magnitude = i64::from_str_radix(digits, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// Returns the mirror list path of a `mirror+file:/path` or `mirror+file:///path` URI.
fn mirror_file_path(uri: &str) -> Option<String> {
    const SCHEME: &str = "mirror+file:";
    let prefix = uri.get(..SCHEME.len())?;
    if !prefix.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let rest = &uri[SCHEME.len()..];
    let path = rest.strip_prefix("//").unwrap_or(rest);
    path.starts_with('/').then(|| path.to_string())
}

fn inspect_yum_global_conf(path: &str, content: &str, violations: &mut Vec<String>) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            if key.trim().eq_ignore_ascii_case("gpgcheck")
                && (val.trim() == "0" || val.trim().eq_ignore_ascii_case("false"))
            {
                violations.push(format!(
                    "{path}:{}: global package manager disables GPG check ({line})",
                    idx + 1
                ));
            }
        }
    }
}

/// Checks that the URI host matches a trusted domain exactly or as a subdomain.
///
/// Rejects substring spoofing such as `https://evil.com/ubuntu.com/repo`.
fn is_uri_trusted(uri: &str, trusted_domains: &[String]) -> bool {
    let Some(host) = extract_uri_host(uri) else {
        return false;
    };
    trusted_domains.iter().any(|domain| {
        host == *domain
            || host
                .strip_suffix(domain.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn extract_uri_host(uri: &str) -> Option<String> {
    let (_, after_scheme) = uri.split_once("://")?;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if host_port.starts_with('[') {
        host_port.split(']').next()?.trim_start_matches('[')
    } else {
        host_port.split(':').next()?
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::sys::rootfs::FIXTURE_META_FILE;
    use crate::sys::RootFsSystemView;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    fn sample_spec() -> PackageReposCheck {
        PackageReposCheck {
            trusted_domains: vec!["ubuntu.com".to_string(), "debian.org".to_string()],
            check_gpg: true,
        }
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, content).expect("write");
    }

    fn audit(root: &Path) -> CheckOutcome {
        let view = RootFsSystemView::from_root(root).expect("view");
        evaluate(&sample_spec(), &view)
    }

    /// DEB822 sources exactly as shipped by the `debian:bookworm` image.
    const BOOKWORM_DEBIAN_SOURCES: &str = "\
Types: deb
# http://snapshot.debian.org/archive/debian/20240101T000000Z
URIs: http://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
# http://snapshot.debian.org/archive/debian-security/20240101T000000Z
URIs: http://deb.debian.org/debian-security
Suites: bookworm-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
";

    #[test]
    fn passes_for_trusted_deb822_sources() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/apt/sources.list.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/apt/sources.list.d/ubuntu.sources"),
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/\nSuites: noble\nComponents: main\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Pass);
    }

    #[test]
    fn rejects_domain_spoofing_in_path_and_suffix() {
        let trusted = vec!["ubuntu.com".to_string()];
        assert!(is_uri_trusted(
            "https://archive.ubuntu.com/ubuntu",
            &trusted
        ));
        assert!(is_uri_trusted("https://ubuntu.com/ubuntu", &trusted));
        assert!(!is_uri_trusted(
            "https://evil.com/ubuntu.com/repo",
            &trusted
        ));
        assert!(!is_uri_trusted("https://notubuntu.com/repo", &trusted));
    }

    #[test]
    fn fails_when_apt_disables_gpg_via_trusted_yes_or_apt_conf() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc/apt/apt.conf.d")).expect("mkdir");
        fs::write(
            dir.path().join("etc/apt/sources.list"),
            "deb [trusted=yes] http://archive.ubuntu.com/ubuntu noble main\n",
        )
        .expect("write");
        fs::write(
            dir.path().join("etc/apt/apt.conf.d/99insecure"),
            "APT::Get::AllowUnauthenticated \"true\";\n",
        )
        .expect("write");

        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Fail);
        assert_eq!(out.details.len(), 2);
    }

    #[test]
    fn warns_when_no_repo_files_exist() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("view");
        let out = evaluate(&sample_spec(), &view);
        assert_eq!(out.status, Status::Warn);
    }

    #[test]
    fn passes_for_debian_one_line_sources_with_options_and_comments() {
        let dir = tempdir().expect("tempdir");
        write(
            dir.path(),
            "etc/apt/sources.list",
            "\
# deb cdrom:[Debian GNU/Linux 12.5.0 _Bookworm_ - Official amd64 DVD Binary-1]/ bookworm main

deb http://deb.debian.org/debian/ bookworm main non-free-firmware
deb-src http://deb.debian.org/debian/ bookworm main non-free-firmware

deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://security.debian.org/debian-security bookworm-security main
deb http://deb.debian.org/debian/ bookworm-updates main # updates
",
        );

        let out = audit(dir.path());
        assert_eq!(out.status, Status::Pass, "{:?}", out.details);
        assert_eq!(
            out.actual.as_deref(),
            Some("4 repository URI(s) across 1 file(s) trusted with GPG intact")
        );
    }

    #[test]
    fn passes_for_debian_deb822_sources_as_shipped_by_bookworm() {
        let dir = tempdir().expect("tempdir");
        write(
            dir.path(),
            "etc/apt/sources.list.d/debian.sources",
            BOOKWORM_DEBIAN_SOURCES,
        );

        let out = audit(dir.path());
        assert_eq!(out.status, Status::Pass, "{:?}", out.details);
        assert_eq!(
            out.actual.as_deref(),
            Some("2 repository URI(s) across 1 file(s) trusted with GPG intact")
        );
    }

    #[test]
    fn passes_with_inline_signed_by_key_block() {
        let dir = tempdir().expect("tempdir");
        write(
            dir.path(),
            "etc/apt/sources.list.d/debian.sources",
            "\
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 mQINBGPL0BUBEADmW5NdOOHwPIJlgPu6JDcKw/NZJPR8lsD3K87ZM18gzyQZJD+w
 -----END PGP PUBLIC KEY BLOCK-----
",
        );

        assert_eq!(audit(dir.path()).status, Status::Pass);
    }

    #[test]
    fn fails_on_untrusted_uri_in_folded_deb822_field() {
        let dir = tempdir().expect("tempdir");
        write(
            dir.path(),
            "etc/apt/sources.list.d/debian.sources",
            "Types: deb\nURIs: http://deb.debian.org/debian\n\thttp://evil.example.com/debian\nSuites: bookworm\nComponents: main\n",
        );

        let out = audit(dir.path());
        assert_eq!(out.status, Status::Fail);
        assert_eq!(out.details.len(), 1);
        assert!(out.details[0].contains("http://evil.example.com/debian"));
    }

    #[test]
    fn fails_on_every_gpg_weakening_option_and_true_spelling() {
        let fields = [
            "Trusted",
            "Allow-Insecure",
            "Allow-Weak",
            "Allow-Downgrade-To-Insecure",
        ];
        for field in fields {
            for value in ["yes", "true", "1"] {
                let one_line = tempdir().expect("tempdir");
                write(
                    one_line.path(),
                    "etc/apt/sources.list",
                    &format!(
                        "deb [{}={value}] http://deb.debian.org/debian bookworm main\n",
                        field.to_ascii_lowercase()
                    ),
                );
                assert_eq!(
                    audit(one_line.path()).status,
                    Status::Fail,
                    "one-line {field}={value}"
                );

                let deb822 = tempdir().expect("tempdir");
                write(
                    deb822.path(),
                    "etc/apt/sources.list.d/debian.sources",
                    &format!(
                        "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm\nComponents: main\n{field}: {value}\n"
                    ),
                );
                assert_eq!(
                    audit(deb822.path()).status,
                    Status::Fail,
                    "DEB822 {field}: {value}"
                );
            }
        }
    }

    #[test]
    fn accepts_false_option_values_and_skips_disabled_stanzas() {
        let dir = tempdir().expect("tempdir");
        write(
            dir.path(),
            "etc/apt/sources.list",
            "deb [allow-insecure=no trusted=0] http://deb.debian.org/debian bookworm main\n",
        );
        write(
            dir.path(),
            "etc/apt/sources.list.d/debian.sources",
            "\
Types: deb
URIs: http://deb.debian.org/debian
Suites: bookworm
Components: main
Allow-Weak: off

Enabled: off
Types: deb
URIs: http://evil.example.com/debian
Suites: bookworm
Components: main
Trusted: yes

Enabled: 0
Types: deb
URIs: http://evil.example.org/debian
Suites: bookworm
Components: main
",
        );

        let out = audit(dir.path());
        assert_eq!(out.status, Status::Pass, "{:?}", out.details);
    }

    #[test]
    fn fails_when_apt_conf_weakens_verification_with_any_true_spelling() {
        let dir = tempdir().expect("tempdir");
        write(
            dir.path(),
            "etc/apt/sources.list.d/debian.sources",
            BOOKWORM_DEBIAN_SOURCES,
        );
        write(
            dir.path(),
            "etc/apt/apt.conf.d/99weak",
            "\
Acquire::AllowInsecureRepositories \"yes\";
Acquire { AllowWeakRepositories \"on\"; };
Acquire::AllowDowngradeToInsecureRepositories \"1\";
APT::Get::AllowUnauthenticated \"false\"; // explicitly disabled
// APT::Get::AllowUnauthenticated \"true\";
",
        );

        let out = audit(dir.path());
        assert_eq!(out.status, Status::Fail);
        assert_eq!(out.details.len(), 3, "{:?}", out.details);
    }

    #[test]
    fn resolves_mirror_file_sources_inside_root() {
        let dir = tempdir().expect("tempdir");
        write(
            dir.path(),
            "etc/apt/sources.list.d/debian.sources",
            "Types: deb\nURIs: mirror+file:///etc/apt/mirrors/debian.list\nSuites: bookworm\nComponents: main\n",
        );
        write(
            dir.path(),
            "etc/apt/sources.list",
            "deb mirror+file:/etc/apt/mirrors/debian-security.list bookworm-security main\n",
        );
        write(
            dir.path(),
            "etc/apt/mirrors/debian.list",
            "# Debian mirrors\nhttps://deb.debian.org/debian\tpriority:1\n\nhttp://ftp.fr.debian.org/debian\n",
        );
        write(
            dir.path(),
            "etc/apt/mirrors/debian-security.list",
            "https://deb.debian.org/debian-security\n",
        );

        let out = audit(dir.path());
        assert_eq!(out.status, Status::Pass, "{:?}", out.details);
        assert_eq!(
            out.actual.as_deref(),
            Some("3 repository URI(s) across 2 file(s) trusted with GPG intact")
        );

        write(
            dir.path(),
            "etc/apt/mirrors/debian.list",
            "https://deb.debian.org/debian\nhttps://mirror.evil.example/debian\n",
        );
        let out = audit(dir.path());
        assert_eq!(out.status, Status::Fail);
        assert!(out.details[0].contains("https://mirror.evil.example/debian"));
    }

    #[test]
    fn warns_when_mirror_list_is_missing_empty_compressed_or_unreadable() {
        let source = |list: &str| {
            format!("Types: deb\nURIs: mirror+file://{list}\nSuites: bookworm\nComponents: main\n")
        };

        let missing = tempdir().expect("tempdir");
        write(
            missing.path(),
            "etc/apt/sources.list.d/debian.sources",
            &source("/etc/apt/mirrors/debian.list"),
        );
        assert_eq!(audit(missing.path()).status, Status::Warn);

        let empty = tempdir().expect("tempdir");
        write(
            empty.path(),
            "etc/apt/sources.list.d/debian.sources",
            &source("/etc/apt/mirrors/debian.list"),
        );
        write(
            empty.path(),
            "etc/apt/mirrors/debian.list",
            "# no mirror\n\n",
        );
        assert_eq!(audit(empty.path()).status, Status::Warn);

        let compressed = tempdir().expect("tempdir");
        write(
            compressed.path(),
            "etc/apt/sources.list.d/debian.sources",
            &source("/etc/apt/mirrors/debian.list.gz"),
        );
        write(
            compressed.path(),
            "etc/apt/mirrors/debian.list.gz",
            "binary",
        );
        assert_eq!(audit(compressed.path()).status, Status::Warn);

        let unreadable = tempdir().expect("tempdir");
        write(
            unreadable.path(),
            "etc/apt/sources.list.d/debian.sources",
            &source("/etc/apt/mirrors/debian.list"),
        );
        write(
            unreadable.path(),
            "etc/apt/mirrors/debian.list",
            "https://deb.debian.org/debian\n",
        );
        write(
            unreadable.path(),
            FIXTURE_META_FILE,
            "[files.\"/etc/apt/mirrors/debian.list\"]\nunreadable = true\n",
        );
        let view = RootFsSystemView::from_root(unreadable.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("view");
        assert_eq!(evaluate(&sample_spec(), &view).status, Status::Warn);
    }

    #[test]
    fn reads_apt_booleans_like_string_to_bool() {
        for truthy in [
            "yes", "TRUE", "with", "on", "Enable", "1", "01", "0x1", "+1",
        ] {
            assert_eq!(apt_bool(truthy), Some(true), "{truthy}");
        }
        for falsy in ["no", "False", "without", "off", "disable", "0", "-0", "0x0"] {
            assert_eq!(apt_bool(falsy), Some(false), "{falsy}");
        }
        for unknown in ["", "2", "-1", "0x", "maybe", "yes please"] {
            assert_eq!(apt_bool(unknown), None, "{unknown}");
        }
    }
}
