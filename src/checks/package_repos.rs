//! `package_repos` check primitive validating APT (`.list` and DEB822 `.sources`) and
//! YUM/DNF repository domains and GPG enforcement.

use crate::checks::{expand_virtual_paths, CheckOutcome};
use crate::rules::schema::PackageReposCheck;
use crate::sys::SystemView;

/// Evaluates package repository trust and GPG signature settings.
pub fn evaluate(spec: &PackageReposCheck, view: &dyn SystemView) -> CheckOutcome {
    let trusted: Vec<String> = spec
        .trusted_domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    let mut repo_files_checked = 0usize;
    let mut urls_checked = 0usize;
    let mut violations = Vec::new();
    let mut unreadable = Vec::new();

    // 1. Legacy APT sources (.list)
    let apt_list_patterns = vec![
        "/etc/apt/sources.list".to_string(),
        "/etc/apt/sources.list.d/*.list".to_string(),
    ];
    let (apt_lists, more_unreadable) = expand_virtual_paths(view, &apt_list_patterns);
    unreadable.extend(more_unreadable);
    for path in apt_lists {
        match view.read_to_string(&path) {
            Ok(content) => {
                repo_files_checked += 1;
                inspect_apt_list(
                    &path,
                    &content,
                    &trusted,
                    spec.check_gpg,
                    &mut urls_checked,
                    &mut violations,
                );
            }
            Err(err) if err.is_not_found() => {}
            Err(err) => unreadable.push(format!("{path}: {err}")),
        }
    }

    // 2. DEB822 APT sources (.sources — Ubuntu 24.04 default)
    let deb822_patterns = vec!["/etc/apt/sources.list.d/*.sources".to_string()];
    let (deb822_files, more_unreadable) = expand_virtual_paths(view, &deb822_patterns);
    unreadable.extend(more_unreadable);
    for path in deb822_files {
        match view.read_to_string(&path) {
            Ok(content) => {
                repo_files_checked += 1;
                inspect_deb822_sources(
                    &path,
                    &content,
                    &trusted,
                    spec.check_gpg,
                    &mut urls_checked,
                    &mut violations,
                );
            }
            Err(err) if err.is_not_found() => {}
            Err(err) => unreadable.push(format!("{path}: {err}")),
        }
    }

    // 3. YUM/DNF repos
    let yum_patterns = vec!["/etc/yum.repos.d/*.repo".to_string()];
    let (yum_files, more_unreadable) = expand_virtual_paths(view, &yum_patterns);
    unreadable.extend(more_unreadable);
    for path in yum_files {
        match view.read_to_string(&path) {
            Ok(content) => {
                repo_files_checked += 1;
                inspect_yum_repo(
                    &path,
                    &content,
                    &trusted,
                    spec.check_gpg,
                    &mut urls_checked,
                    &mut violations,
                );
            }
            Err(err) if err.is_not_found() => {}
            Err(err) => unreadable.push(format!("{path}: {err}")),
        }
    }

    // 4. Global APT & YUM/DNF GPG settings
    if spec.check_gpg {
        let apt_conf_patterns = vec![
            "/etc/apt/apt.conf".to_string(),
            "/etc/apt/apt.conf.d/*".to_string(),
        ];
        let (apt_confs, more_unreadable) = expand_virtual_paths(view, &apt_conf_patterns);
        unreadable.extend(more_unreadable);
        for path in apt_confs {
            match view.read_to_string(&path) {
                Ok(content) => inspect_apt_conf(&path, &content, &mut violations),
                Err(err) if err.is_not_found() => {}
                Err(err) => unreadable.push(format!("{path}: {err}")),
            }
        }

        for path in ["/etc/yum.conf", "/etc/dnf/dnf.conf"] {
            match view.read_to_string(path) {
                Ok(content) => inspect_yum_global_conf(path, &content, &mut violations),
                Err(err) if err.is_not_found() => {}
                Err(err) => unreadable.push(format!("{path}: {err}")),
            }
        }
    }

    unreadable.sort();
    unreadable.dedup();

    let expected = if spec.check_gpg {
        "only trusted repository domains and GPG verification enabled"
    } else {
        "only trusted repository domains"
    };

    if !violations.is_empty() {
        let actual = format!("{} repository/GPG violation(s)", violations.len());
        let mut details = violations;
        details.extend(unreadable);
        return CheckOutcome::fail(expected, actual, details);
    }

    if repo_files_checked == 0 {
        return CheckOutcome::warn(
            expected,
            "no package repository configuration files found",
            if unreadable.is_empty() {
                vec!["neither APT nor YUM/DNF repository files were found".to_string()]
            } else {
                unreadable
            },
        );
    }

    if !unreadable.is_empty() {
        return CheckOutcome::warn(
            expected,
            format!(
                "{urls_checked} repository URI(s) trusted, but {} path(s) unreadable",
                unreadable.len()
            ),
            unreadable,
        );
    }

    CheckOutcome::pass(
        expected,
        format!(
            "{urls_checked} repository URI(s) across {repo_files_checked} file(s) trusted with GPG intact"
        ),
    )
}

fn inspect_apt_list(
    path: &str,
    content: &str,
    trusted: &[String],
    check_gpg: bool,
    urls_checked: &mut usize,
    violations: &mut Vec<String>,
) {
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
        let mut rest = rest.trim_start();
        if let Some(after_open) = rest.strip_prefix('[') {
            if let Some((opts, after_close)) = after_open.split_once(']') {
                if check_gpg && apt_options_disable_gpg(opts) {
                    violations.push(format!(
                        "{path}:{}: APT source disables GPG verification ([{opts}])",
                        idx + 1
                    ));
                }
                rest = after_close.trim_start();
            }
        }
        if let Some(uri) = rest.split_whitespace().next() {
            *urls_checked += 1;
            if !is_uri_trusted(uri, trusted) {
                violations.push(format!(
                    "{path}:{}: untrusted repository URI '{uri}'",
                    idx + 1
                ));
            }
        }
    }
}

fn apt_options_disable_gpg(opts: &str) -> bool {
    opts.split_whitespace().any(|tok| {
        tok.eq_ignore_ascii_case("trusted=yes") || tok.eq_ignore_ascii_case("allow-insecure=yes")
    })
}

fn inspect_deb822_sources(
    path: &str,
    content: &str,
    trusted: &[String],
    check_gpg: bool,
    urls_checked: &mut usize,
    violations: &mut Vec<String>,
) {
    let mut enabled = true;
    let mut stanza_uris: Vec<String> = Vec::new();
    let mut stanza_trusted_yes = false;

    let flush = |enabled: bool,
                 stanza_uris: &mut Vec<String>,
                 stanza_trusted_yes: &mut bool,
                 urls_checked: &mut usize,
                 violations: &mut Vec<String>| {
        if enabled {
            for uri in stanza_uris.drain(..) {
                *urls_checked += 1;
                if !is_uri_trusted(&uri, trusted) {
                    violations.push(format!("{path}: untrusted DEB822 repository URI '{uri}'"));
                }
            }
            if check_gpg && *stanza_trusted_yes {
                violations.push(format!("{path}: DEB822 stanza sets 'Trusted: yes'"));
            }
        } else {
            stanza_uris.clear();
        }
        *stanza_trusted_yes = false;
    };

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            flush(
                enabled,
                &mut stanza_uris,
                &mut stanza_trusted_yes,
                urls_checked,
                violations,
            );
            enabled = true;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim();
            let val = val.trim();
            if key.eq_ignore_ascii_case("Enabled") {
                enabled = !val.eq_ignore_ascii_case("no") && !val.eq_ignore_ascii_case("false");
            } else if key.eq_ignore_ascii_case("URIs") {
                for uri in val.split_whitespace() {
                    stanza_uris.push(uri.to_string());
                }
            } else if key.eq_ignore_ascii_case("Trusted") && val.eq_ignore_ascii_case("yes") {
                stanza_trusted_yes = true;
            }
        }
    }
    flush(
        enabled,
        &mut stanza_uris,
        &mut stanza_trusted_yes,
        urls_checked,
        violations,
    );
}

fn inspect_yum_repo(
    path: &str,
    content: &str,
    trusted: &[String],
    check_gpg: bool,
    urls_checked: &mut usize,
    violations: &mut Vec<String>,
) {
    let mut enabled = true;
    let mut stanza_urls: Vec<String> = Vec::new();
    let mut gpg_disabled = false;

    let flush = |enabled: bool,
                 stanza_urls: &mut Vec<String>,
                 gpg_disabled: &mut bool,
                 urls_checked: &mut usize,
                 violations: &mut Vec<String>| {
        if enabled {
            for uri in stanza_urls.drain(..) {
                *urls_checked += 1;
                if !is_uri_trusted(&uri, trusted) {
                    violations.push(format!("{path}: untrusted YUM/DNF repository URI '{uri}'"));
                }
            }
            if check_gpg && *gpg_disabled {
                violations.push(format!(
                    "{path}: repository disables GPG check (gpgcheck=0)"
                ));
            }
        } else {
            stanza_urls.clear();
        }
        *gpg_disabled = false;
    };

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush(
                enabled,
                &mut stanza_urls,
                &mut gpg_disabled,
                urls_checked,
                violations,
            );
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
    flush(
        enabled,
        &mut stanza_urls,
        &mut gpg_disabled,
        urls_checked,
        violations,
    );
}

fn inspect_apt_conf(path: &str, content: &str, violations: &mut Vec<String>) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let disables = (lower.contains("allowunauthenticated")
            || lower.contains("allowinsecurerepositories"))
            && (lower.contains("true") || lower.contains("\"1\""));
        if disables {
            violations.push(format!(
                "{path}:{}: APT configuration weakens GPG verification ({line})",
                idx + 1
            ));
        }
    }
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
    use crate::sys::RootFsSystemView;
    use std::fs;
    use tempfile::tempdir;

    fn sample_spec() -> PackageReposCheck {
        PackageReposCheck {
            trusted_domains: vec!["ubuntu.com".to_string(), "debian.org".to_string()],
            check_gpg: true,
        }
    }

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
}
