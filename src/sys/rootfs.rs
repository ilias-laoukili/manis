//! Filesystem-backed [`SystemView`] supporting both live Linux `/` and `--root <path>` fixtures.

use crate::error::{ManisError, SystemError};
use crate::sys::{DirEntryInfo, FileMeta, SystemView, WalkReport, WalkedFile};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Optional metadata overlay filename recognized ONLY in `--root <path>` mode.
pub const FIXTURE_META_FILE: &str = ".manis-meta.toml";

/// Deserialized representation of `.manis-meta.toml` inside a `--root` fixture directory.
#[derive(Debug, Clone, Default, Deserialize)]
struct FixtureMetaOverlay {
    #[serde(default)]
    files: BTreeMap<String, FixtureEntryOverride>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct FixtureEntryOverride {
    /// Octal permission/special mode string (e.g. `"4755"`, `"2755"`, `"4777"`).
    mode: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// When `true`, reading this path simulates `SystemError::PermissionDenied`.
    #[serde(default)]
    unreadable: bool,
    /// Optional simulated symlink target (e.g. `"/dev/null"` for masked systemd units).
    /// Only honored in `--root` fixture mode, never in live `/` mode.
    symlink_target: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct ParsedOverlay {
    entries: BTreeMap<String, ParsedEntryOverride>,
}

#[derive(Debug, Clone, Default)]
struct ParsedEntryOverride {
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    unreadable: bool,
    symlink_target: Option<String>,
}

impl ParsedOverlay {
    fn load(path: &Path) -> Result<Self, ManisError> {
        let raw = fs::read_to_string(path).map_err(|e| {
            ManisError::Config(format!(
                "failed to read fixture metadata overlay '{}': {e}",
                path.display()
            ))
        })?;
        let parsed: FixtureMetaOverlay = toml::from_str(&raw).map_err(|e| {
            ManisError::Config(format!(
                "invalid fixture metadata overlay '{}': {e}",
                path.display()
            ))
        })?;

        let mut entries = BTreeMap::new();
        for (vpath, ov) in parsed.files {
            let norm = normalize_virtual_path(&vpath)
                .map_err(|e| ManisError::Config(format!("invalid path in overlay: {e}")))?;
            let mode = match ov.mode {
                Some(ref s) => {
                    let stripped = s.trim().trim_start_matches("0o").trim_start_matches("0O");
                    let val = u32::from_str_radix(stripped, 8).map_err(|_| {
                        ManisError::Config(format!(
                            "invalid octal mode '{s}' for '{norm}' in {}",
                            path.display()
                        ))
                    })?;
                    Some(val)
                }
                None => None,
            };
            entries.insert(
                norm,
                ParsedEntryOverride {
                    mode,
                    uid: ov.uid,
                    gid: ov.gid,
                    unreadable: ov.unreadable,
                    symlink_target: ov.symlink_target,
                },
            );
        }
        Ok(Self { entries })
    }

    fn get(&self, vpath: &str) -> Option<&ParsedEntryOverride> {
        self.entries.get(vpath)
    }

    fn is_unreadable(&self, vpath: &str) -> bool {
        self.entries.get(vpath).is_some_and(|e| e.unreadable)
    }
}

/// [`SystemView`] backed by either the live root `/` or an offline `--root <path>` directory.
#[derive(Debug, Clone)]
pub struct RootFsSystemView {
    root: PathBuf,
    display_root: String,
    /// `Some(...)` ONLY when constructed via [`Self::from_root`] and `.manis-meta.toml` exists.
    /// Always `None` in live host mode (`/`).
    overlay: Option<ParsedOverlay>,
}

impl RootFsSystemView {
    /// Creates a live host view anchored at `/`.
    ///
    /// Never loads `.manis-meta.toml`.
    pub fn live() -> Self {
        Self {
            root: PathBuf::from("/"),
            display_root: "/".to_string(),
            overlay: None,
        }
    }

    /// Creates an offline view anchored at `root`.
    ///
    /// Loads `<root>/.manis-meta.toml` if and only if present inside the fixture directory.
    pub fn from_root(root: impl AsRef<Path>) -> Result<Self, ManisError> {
        let root_path = root.as_ref();
        if !root_path.exists() {
            return Err(ManisError::System(SystemError::NotFound(
                root_path.display().to_string(),
            )));
        }
        if !root_path.is_dir() {
            return Err(ManisError::Config(format!(
                "--root path '{}' is not a directory",
                root_path.display()
            )));
        }

        let overlay_path = root_path.join(FIXTURE_META_FILE);
        let overlay = if overlay_path.is_file() {
            Some(ParsedOverlay::load(&overlay_path)?)
        } else {
            None
        };

        Ok(Self {
            root: root_path.to_path_buf(),
            display_root: root_path.display().to_string(),
            overlay,
        })
    }

    fn resolve(&self, vpath: &str) -> Result<(String, PathBuf), SystemError> {
        let norm = normalize_virtual_path(vpath)?;
        let rel = norm.trim_start_matches('/');
        let host_path = if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        };
        Ok((norm, host_path))
    }

    fn check_overlay_readable(&self, norm: &str) -> Result<(), SystemError> {
        if self
            .overlay
            .as_ref()
            .is_some_and(|ov| ov.is_unreadable(norm))
        {
            return Err(SystemError::PermissionDenied(norm.to_string()));
        }
        Ok(())
    }

    fn apply_overlay(&self, norm: &str, mut meta: FileMeta) -> FileMeta {
        if let Some(ov) = self.overlay.as_ref().and_then(|o| o.get(norm)) {
            if let Some(m) = ov.mode {
                meta.mode = (meta.mode & !0o7777) | (m & 0o7777);
            }
            if let Some(uid) = ov.uid {
                meta.uid = uid;
            }
            if let Some(gid) = ov.gid {
                meta.gid = gid;
            }
        }
        meta
    }

    fn is_internal_meta_file(&self, norm: &str) -> bool {
        self.overlay.is_some() && norm == format!("/{FIXTURE_META_FILE}")
    }

    fn walk_dir_recursive(
        &self,
        vdir: &str,
        skip_dirs: &[String],
        report: &mut WalkReport,
    ) -> Result<(), SystemError> {
        if should_skip(vdir, skip_dirs) {
            return Ok(());
        }
        if self.check_overlay_readable(vdir).is_err() {
            report.unreadable_paths.push(vdir.to_string());
            return Ok(());
        }

        let entries = match self.read_dir(vdir) {
            Ok(list) => list,
            Err(err) if err.is_permission_denied() => {
                report.unreadable_paths.push(vdir.to_string());
                return Ok(());
            }
            Err(err) if err.is_not_found() => return Ok(()),
            Err(err) => {
                report.unreadable_paths.push(format!("{vdir} ({err})"));
                return Ok(());
            }
        };

        for entry in entries {
            if self.is_internal_meta_file(&entry.path) {
                continue;
            }
            if entry.is_symlink {
                continue;
            }
            if entry.is_dir {
                if !should_skip(&entry.path, skip_dirs) {
                    if let Ok(meta) = self.metadata(&entry.path) {
                        report.dirs.push(WalkedFile {
                            path: entry.path.clone(),
                            meta,
                        });
                    }
                    self.walk_dir_recursive(&entry.path, skip_dirs, report)?;
                }
            } else if entry.is_file {
                match self.metadata(&entry.path) {
                    Ok(meta) => report.files.push(WalkedFile {
                        path: entry.path,
                        meta,
                    }),
                    Err(_) => report.unreadable_paths.push(entry.path),
                }
            }
        }
        Ok(())
    }
}

impl SystemView for RootFsSystemView {
    fn display_root(&self) -> &str {
        &self.display_root
    }

    fn read_to_string(&self, path: &str) -> Result<String, SystemError> {
        let (norm, host_path) = self.resolve(path)?;
        self.check_overlay_readable(&norm)?;
        fs::read_to_string(&host_path).map_err(|e| SystemError::from_io(norm, &e))
    }

    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, SystemError> {
        let (norm, host_path) = self.resolve(path)?;
        self.check_overlay_readable(&norm)?;
        fs::read(&host_path).map_err(|e| SystemError::from_io(norm, &e))
    }

    fn exists(&self, path: &str) -> bool {
        self.resolve(path)
            .is_ok_and(|(norm, host_path)| !self.is_internal_meta_file(&norm) && host_path.exists())
    }

    fn metadata(&self, path: &str) -> Result<FileMeta, SystemError> {
        let (norm, host_path) = self.resolve(path)?;
        let md = fs::symlink_metadata(&host_path).map_err(|e| SystemError::from_io(&norm, &e))?;
        let mut base = extract_file_meta(&md);
        if self
            .overlay
            .as_ref()
            .and_then(|o| o.get(&norm))
            .is_some_and(|ov| ov.symlink_target.is_some())
        {
            base.is_symlink = true;
            base.is_file = false;
        }
        Ok(self.apply_overlay(&norm, base))
    }

    fn read_link(&self, path: &str) -> Result<String, SystemError> {
        let (norm, host_path) = self.resolve(path)?;
        self.check_overlay_readable(&norm)?;
        if let Some(target) = self
            .overlay
            .as_ref()
            .and_then(|o| o.get(&norm))
            .and_then(|ov| ov.symlink_target.as_ref())
        {
            return Ok(target.clone());
        }
        let target = fs::read_link(&host_path).map_err(|e| SystemError::from_io(&norm, &e))?;
        Ok(target.to_string_lossy().into_owned())
    }

    fn read_dir(&self, path: &str) -> Result<Vec<DirEntryInfo>, SystemError> {
        let (norm, host_path) = self.resolve(path)?;
        self.check_overlay_readable(&norm)?;
        let read = fs::read_dir(&host_path).map_err(|e| SystemError::from_io(&norm, &e))?;
        let mut out = Vec::new();
        for item in read {
            let entry = item.map_err(|e| SystemError::from_io(&norm, &e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let vpath = if norm == "/" {
                format!("/{name}")
            } else {
                format!("{norm}/{name}")
            };
            if self.is_internal_meta_file(&vpath) {
                continue;
            }
            let ft = entry
                .file_type()
                .map_err(|e| SystemError::from_io(&vpath, &e))?;
            out.push(DirEntryInfo {
                name,
                path: vpath,
                is_file: ft.is_file(),
                is_dir: ft.is_dir(),
                is_symlink: ft.is_symlink(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn walk_files(&self, roots: &[&str], skip_dirs: &[&str]) -> Result<WalkReport, SystemError> {
        let norm_skips: Vec<String> = skip_dirs
            .iter()
            .filter_map(|s| normalize_virtual_path(s).ok())
            .collect();

        let mut report = WalkReport::default();
        for root in roots {
            let norm = normalize_virtual_path(root)?;
            self.walk_dir_recursive(&norm, &norm_skips, &mut report)?;
        }
        report.files.sort_by(|a, b| a.path.cmp(&b.path));
        report.dirs.sort_by(|a, b| a.path.cmp(&b.path));
        report.unreadable_paths.sort();
        report.unreadable_paths.dedup();
        Ok(report)
    }

    fn kernel_release(&self) -> Result<String, SystemError> {
        match self.read_to_string("/proc/sys/kernel/osrelease") {
            Ok(content) => {
                let rel = content.trim();
                if !rel.is_empty() {
                    return Ok(rel.to_string());
                }
            }
            Err(err) if err.is_permission_denied() => return Err(err),
            Err(_) => {}
        }

        // Fallback: inspect `/boot/config-*` when `/proc/sys/kernel/osrelease` is absent
        // (common on mounted offline rootfs images).
        if let Ok(entries) = self.read_dir("/boot") {
            let mut releases: Vec<String> = entries
                .into_iter()
                .filter(|e| e.is_file)
                .filter_map(|e| e.name.strip_prefix("config-").map(ToString::to_string))
                .filter(|s| !s.is_empty())
                .collect();
            releases.sort();
            if let Some(first) = releases.into_iter().next() {
                return Ok(first);
            }
        }

        Err(SystemError::NotFound(
            "/proc/sys/kernel/osrelease".to_string(),
        ))
    }
}

/// Normalizes a virtual Unix path (e.g. `etc/sudoers` -> `/etc/sudoers`) and rejects `..` traversal.
pub fn normalize_virtual_path(vpath: &str) -> Result<String, SystemError> {
    let mut parts: Vec<&str> = Vec::new();
    for comp in Path::new(vpath).components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(SystemError::PathTraversal(vpath.to_string()));
            }
            Component::Normal(os) => {
                let s = os
                    .to_str()
                    .ok_or_else(|| SystemError::PathTraversal(vpath.to_string()))?;
                parts.push(s);
            }
        }
    }
    if parts.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", parts.join("/")))
    }
}

fn should_skip(vdir: &str, skip_dirs: &[String]) -> bool {
    skip_dirs.iter().any(|skip| {
        vdir == skip
            || vdir
                .strip_prefix(skip.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

#[cfg(unix)]
fn extract_file_meta(md: &fs::Metadata) -> FileMeta {
    use std::os::unix::fs::MetadataExt;
    FileMeta {
        mode: md.mode(),
        uid: md.uid(),
        gid: md.gid(),
        is_file: md.is_file(),
        is_dir: md.is_dir(),
        is_symlink: md.file_type().is_symlink(),
    }
}

#[cfg(not(unix))]
fn extract_file_meta(md: &fs::Metadata) -> FileMeta {
    FileMeta {
        mode: if md.permissions().readonly() {
            0o444
        } else {
            0o644
        },
        uid: 0,
        gid: 0,
        is_file: md.is_file(),
        is_dir: md.is_dir(),
        is_symlink: md.file_type().is_symlink(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_parent_dir_traversal() {
        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("root view");
        let err = view.read_to_string("/etc/../../etc/passwd").unwrap_err();
        assert!(matches!(err, SystemError::PathTraversal(_)));
    }

    #[test]
    fn overlay_applies_mode_and_unreadable_in_root_mode() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("usr/bin")).expect("mkdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("usr/bin/custom"), b"bin").expect("write");
        fs::write(dir.path().join("etc/sudoers"), b"root ALL=(ALL) ALL\n").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            r#"
[files."/usr/bin/custom"]
mode = "4777"
uid = 0
gid = 0

[files."/etc/sudoers"]
unreadable = true
"#,
        )
        .expect("write overlay");

        let view = RootFsSystemView::from_root(dir.path()).expect("root view");
        let meta = view.metadata("/usr/bin/custom").expect("metadata");
        assert!(meta.is_suid());
        assert!(meta.is_world_writable());
        assert_eq!(meta.perm_bits(), 0o4777);

        let err = view.read_to_string("/etc/sudoers").unwrap_err();
        assert!(err.is_permission_denied());

        // Internal meta file is hidden from read_dir and walk_files
        let root_entries = view.read_dir("/").expect("read_dir");
        assert!(!root_entries.iter().any(|e| e.name == FIXTURE_META_FILE));
    }

    #[test]
    fn live_mode_never_enables_overlay() {
        let live = RootFsSystemView::live();
        assert!(live.overlay.is_none());
        assert_eq!(live.display_root(), "/");
    }
}
