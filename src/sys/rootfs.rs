//! Filesystem-backed [`SystemView`] supporting both live Linux `/` and `--root <path>` fixtures.
//!
//! # Symlink confinement in `--root` mode
//!
//! In `--root <path>` mode every virtual path is resolved component by component inside the root
//! directory, like a `chroot`: absolute symlink targets are re-rooted, `..` never climbs above the
//! root, and resolution fails with [`SystemError::SymlinkLoop`] after [`MAX_SYMLINK_HOPS`] links.
//! The host kernel only ever receives paths whose components below the root were checked not to
//! be symlinks, so no operation can reach a file of the host.
//!
//! Limitation: resolution is path based (`openat2` / `O_NOFOLLOW` are not reachable without
//! `unsafe` code or extra dependencies), so a root modified concurrently during an audit could
//! race between the check and the use of a component. Audited roots are expected to be static,
//! ideally mounted read-only.
//!
//! Live mode (`/`) is unchanged: the kernel resolves paths against the real host root.

use crate::error::{ManisError, SystemError};
use crate::sys::{DirEntryInfo, FileMeta, SystemView, WalkReport, WalkedFile};
use serde::Deserialize;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Fixture metadata overlay filename, applied ONLY on explicit opt-in in `--root <path>` mode
/// ([`RootFsSystemView::with_fixture_meta`], CLI `--fixture-meta`).
pub const FIXTURE_META_FILE: &str = ".manis-meta.toml";

/// Maximum number of symbolic links followed while resolving one path in `--root` mode
/// (the same limit as Linux `MAXSYMLINKS`).
pub const MAX_SYMLINK_HOPS: usize = 40;

/// Whether a symlink in the final path component is followed during `--root` resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalComponent {
    /// Follow a final symlink (`read_to_string`, `read_bytes`, `exists`, `read_dir`).
    Follow,
    /// Keep a final symlink as is, so `lstat` / `readlink` see the link itself (`metadata`,
    /// `read_link`).
    NoFollow,
}

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
    /// `Some(...)` ONLY after the explicit [`Self::with_fixture_meta`] opt-in on a `--root` view.
    /// Always `None` in live host mode (`/`).
    overlay: Option<ParsedOverlay>,
    /// `true` ONLY when constructed via [`Self::from_root`]: paths and symlinks are resolved
    /// inside `root` (see the module documentation). Always `false` in live host mode (`/`).
    confined: bool,
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
            confined: false,
        }
    }

    /// Creates an offline view anchored at `root`.
    ///
    /// Every path, symlinks included, is resolved inside `root` (see the module documentation).
    /// A `<root>/.manis-meta.toml` is never applied here: it stays an ordinary file of the audited
    /// tree unless [`Self::with_fixture_meta`] explicitly opts in.
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

        Ok(Self {
            root: root_path.to_path_buf(),
            display_root: root_path.display().to_string(),
            overlay: None,
            confined: true,
        })
    }

    /// Applies the `<root>/.manis-meta.toml` fixture overlay (CLI `--fixture-meta`).
    ///
    /// The overlay simulates permission modes, ownership, unreadable files and symlinks that Git
    /// cannot store. It lets the audited tree rewrite its own metadata, so it is opt-in and meant
    /// for trusted test fixtures only. It is located through confined resolution, so a symlinked
    /// overlay can never point outside the root.
    ///
    /// Fails on a live view, or when the overlay is missing, not a regular file, or invalid.
    pub fn with_fixture_meta(mut self) -> Result<Self, ManisError> {
        if !self.confined {
            return Err(ManisError::Config(
                "fixture metadata overlays are only available with --root".to_string(),
            ));
        }
        let vpath = format!("/{FIXTURE_META_FILE}");
        let overlay_path = match self.host_path(&vpath, FinalComponent::Follow) {
            Ok(path) if path.is_file() => path,
            Ok(_) => {
                return Err(ManisError::Config(format!(
                    "fixture metadata overlay {vpath} under '{}' is not a regular file",
                    self.display_root
                )));
            }
            Err(err) => {
                return Err(ManisError::Config(format!(
                    "fixture metadata overlay unavailable under '{}': {err}",
                    self.display_root
                )));
            }
        };
        self.overlay = Some(ParsedOverlay::load(&overlay_path)?);
        Ok(self)
    }

    /// Maps a normalized virtual path to the host path to operate on.
    ///
    /// In `--root` mode the path is resolved inside the root by [`resolve_in_root`]; in live mode
    /// the kernel resolves it against the real `/`, exactly as before.
    fn host_path(&self, norm: &str, last: FinalComponent) -> Result<PathBuf, SystemError> {
        if self.confined {
            return resolve_in_root(&self.root, norm, last);
        }
        let rel = norm.trim_start_matches('/');
        Ok(if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        })
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

    /// `lstat`-style metadata of an already resolved host path, with fixture overlays applied.
    fn metadata_at(&self, norm: &str, host_path: &Path) -> Result<FileMeta, SystemError> {
        let md = fs::symlink_metadata(host_path).map_err(|e| SystemError::from_io(norm, &e))?;
        let mut base = extract_file_meta(&md);
        if self
            .overlay
            .as_ref()
            .and_then(|o| o.get(norm))
            .is_some_and(|ov| ov.symlink_target.is_some())
        {
            base.is_symlink = true;
            base.is_file = false;
        }
        Ok(self.apply_overlay(norm, base))
    }

    /// Sorted listing of an already resolved host directory, hiding the internal overlay file.
    fn read_dir_at(&self, norm: &str, host_path: &Path) -> Result<Vec<DirEntryInfo>, SystemError> {
        let read = fs::read_dir(host_path).map_err(|e| SystemError::from_io(norm, &e))?;
        let mut out = Vec::new();
        for item in read {
            let entry = item.map_err(|e| SystemError::from_io(norm, &e))?;
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

    /// Recursively walks `vdir`.
    ///
    /// `host_dir` is `None` for a walk root, which is resolved once through [`Self::host_path`].
    /// Descendants are reached by joining entry names onto their already resolved parent:
    /// symlink entries are never traversed, so no further resolution is needed.
    fn walk_dir_recursive(
        &self,
        vdir: &str,
        host_dir: Option<&Path>,
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

        let listing = match host_dir {
            Some(dir) => self
                .read_dir_at(vdir, dir)
                .map(|entries| (dir.to_path_buf(), entries)),
            None => self
                .host_path(vdir, FinalComponent::Follow)
                .and_then(|dir| self.read_dir_at(vdir, &dir).map(|entries| (dir, entries))),
        };
        let (dir, entries) = match listing {
            Ok(found) => found,
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
            let host_entry = dir.join(&entry.name);
            if entry.is_dir {
                if !should_skip(&entry.path, skip_dirs) {
                    if let Ok(meta) = self.metadata_at(&entry.path, &host_entry) {
                        report.dirs.push(WalkedFile {
                            path: entry.path.clone(),
                            meta,
                        });
                    }
                    self.walk_dir_recursive(&entry.path, Some(&host_entry), skip_dirs, report)?;
                }
            } else if entry.is_file {
                match self.metadata_at(&entry.path, &host_entry) {
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
        let norm = normalize_virtual_path(path)?;
        self.check_overlay_readable(&norm)?;
        let host_path = self.host_path(&norm, FinalComponent::Follow)?;
        fs::read_to_string(&host_path).map_err(|e| SystemError::from_io(norm, &e))
    }

    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, SystemError> {
        let norm = normalize_virtual_path(path)?;
        self.check_overlay_readable(&norm)?;
        let host_path = self.host_path(&norm, FinalComponent::Follow)?;
        fs::read(&host_path).map_err(|e| SystemError::from_io(norm, &e))
    }

    fn exists(&self, path: &str) -> bool {
        normalize_virtual_path(path).is_ok_and(|norm| {
            !self.is_internal_meta_file(&norm)
                && self
                    .host_path(&norm, FinalComponent::Follow)
                    .is_ok_and(|host_path| host_path.exists())
        })
    }

    fn metadata(&self, path: &str) -> Result<FileMeta, SystemError> {
        let norm = normalize_virtual_path(path)?;
        let host_path = self.host_path(&norm, FinalComponent::NoFollow)?;
        self.metadata_at(&norm, &host_path)
    }

    fn read_link(&self, path: &str) -> Result<String, SystemError> {
        let norm = normalize_virtual_path(path)?;
        self.check_overlay_readable(&norm)?;
        if let Some(target) = self
            .overlay
            .as_ref()
            .and_then(|o| o.get(&norm))
            .and_then(|ov| ov.symlink_target.as_ref())
        {
            return Ok(target.clone());
        }
        let host_path = self.host_path(&norm, FinalComponent::NoFollow)?;
        let target = fs::read_link(&host_path).map_err(|e| SystemError::from_io(&norm, &e))?;
        Ok(target.to_string_lossy().into_owned())
    }

    fn read_dir(&self, path: &str) -> Result<Vec<DirEntryInfo>, SystemError> {
        let norm = normalize_virtual_path(path)?;
        self.check_overlay_readable(&norm)?;
        let host_path = self.host_path(&norm, FinalComponent::Follow)?;
        self.read_dir_at(&norm, &host_path)
    }

    fn walk_files(&self, roots: &[&str], skip_dirs: &[&str]) -> Result<WalkReport, SystemError> {
        let norm_skips: Vec<String> = skip_dirs
            .iter()
            .filter_map(|s| normalize_virtual_path(s).ok())
            .collect();

        let mut report = WalkReport::default();
        for root in roots {
            let norm = normalize_virtual_path(root)?;
            self.walk_dir_recursive(&norm, None, &norm_skips, &mut report)?;
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

/// Resolves a normalized virtual path inside `root`, never leaving it (see the module docs).
///
/// Each component is inspected with `lstat` from `root` downwards and symlinks are expanded in
/// user space: an absolute target restarts from `root`, `..` stops at `root` (like `chroot`), and
/// more than [`MAX_SYMLINK_HOPS`] links fail with [`SystemError::SymlinkLoop`]. With
/// [`FinalComponent::NoFollow`] a final symlink is kept as is.
fn resolve_in_root(root: &Path, norm: &str, last: FinalComponent) -> Result<PathBuf, SystemError> {
    let mut resolved: Vec<OsString> = Vec::new();
    let mut pending: VecDeque<OsString> = norm
        .split('/')
        .filter(|part| !part.is_empty())
        .map(OsString::from)
        .collect();
    let mut hops = 0;

    while let Some(component) = pending.pop_front() {
        if component == ".." {
            // Only symlink targets produce `..`; it is clamped at the root, like `chroot`.
            resolved.pop();
            continue;
        }
        if pending.is_empty() && last == FinalComponent::NoFollow {
            resolved.push(component);
            break;
        }

        let candidate = join_under(root, &resolved).join(&component);
        let meta = fs::symlink_metadata(&candidate).map_err(|e| SystemError::from_io(norm, &e))?;
        if meta.file_type().is_symlink() {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Err(SystemError::SymlinkLoop(norm.to_string()));
            }
            let target = fs::read_link(&candidate).map_err(|e| SystemError::from_io(norm, &e))?;
            if target.has_root() {
                // Absolute targets are re-rooted: `/x` means `<root>/x`.
                resolved.clear();
            }
            let mut expanded: VecDeque<OsString> = target
                .components()
                .filter_map(|c| match c {
                    Component::Normal(part) => Some(part.to_os_string()),
                    Component::ParentDir => Some(OsString::from("..")),
                    Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
                })
                .collect();
            expanded.extend(pending);
            pending = expanded;
        } else if !pending.is_empty() && !meta.is_dir() {
            return Err(SystemError::Io {
                path: norm.to_string(),
                message: "not a directory".to_string(),
            });
        } else {
            resolved.push(component);
        }
    }

    Ok(join_under(root, &resolved))
}

/// Joins already resolved components (none of them a symlink) under `root`.
fn join_under(root: &Path, components: &[OsString]) -> PathBuf {
    let mut path = root.to_path_buf();
    path.extend(components);
    path
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
    fn overlay_applies_mode_and_unreadable_with_fixture_meta_opt_in() {
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

        let view = RootFsSystemView::from_root(dir.path())
            .and_then(RootFsSystemView::with_fixture_meta)
            .expect("root view");
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
    fn overlay_present_in_root_is_ignored_by_default() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        fs::write(dir.path().join("etc/sudoers"), b"root ALL=(ALL) ALL\n").expect("write");
        fs::write(
            dir.path().join(FIXTURE_META_FILE),
            "[files.\"/etc/sudoers\"]\nmode = \"4777\"\nunreadable = true\n",
        )
        .expect("write overlay");

        let view = RootFsSystemView::from_root(dir.path()).expect("root view");
        assert!(view.overlay.is_none());
        // The forged metadata is not applied...
        assert!(view.read_to_string("/etc/sudoers").is_ok());
        assert!(!view.metadata("/etc/sudoers").expect("metadata").is_suid());
        // ...and the overlay is audited as an ordinary file of the tree.
        let root_entries = view.read_dir("/").expect("read_dir");
        assert!(root_entries.iter().any(|e| e.name == FIXTURE_META_FILE));
    }

    #[test]
    fn fixture_meta_opt_in_requires_root_and_an_overlay() {
        assert!(matches!(
            RootFsSystemView::live().with_fixture_meta(),
            Err(ManisError::Config(_))
        ));

        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("root view");
        assert!(matches!(
            view.with_fixture_meta(),
            Err(ManisError::Config(_))
        ));
    }

    #[test]
    fn live_mode_never_enables_overlay() {
        let live = RootFsSystemView::live();
        assert!(live.overlay.is_none());
        assert_eq!(live.display_root(), "/");
    }

    #[test]
    fn live_mode_keeps_kernel_path_resolution() {
        let live = RootFsSystemView::live();
        assert!(!live.confined);
        assert_eq!(
            live.host_path("/etc/hosts", FinalComponent::Follow)
                .expect("host path"),
            PathBuf::from("/etc/hosts")
        );

        let dir = tempdir().expect("tempdir");
        let view = RootFsSystemView::from_root(dir.path()).expect("root view");
        assert!(view.confined);
    }

    #[cfg(unix)]
    fn write_file(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, content).expect("write");
    }

    #[cfg(unix)]
    fn make_link(root: &Path, rel: &str, target: impl AsRef<Path>) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::os::unix::fs::symlink(target, path).expect("symlink");
    }

    #[cfg(unix)]
    #[test]
    fn absolute_symlink_to_host_file_is_resolved_inside_root() {
        let host = tempdir().expect("host dir");
        write_file(host.path(), "secret.txt", "HOST-SECRET");
        let root = tempdir().expect("root");
        make_link(root.path(), "etc/leak", host.path().join("secret.txt"));

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        assert!(matches!(
            view.read_to_string("/etc/leak"),
            Err(SystemError::NotFound(_))
        ));
        assert!(matches!(
            view.read_bytes("/etc/leak"),
            Err(SystemError::NotFound(_))
        ));
        assert!(!view.exists("/etc/leak"));
        // The link itself stays visible as a link.
        assert!(view.metadata("/etc/leak").expect("lstat").is_symlink);
    }

    #[cfg(unix)]
    #[test]
    fn absolute_symlink_inside_root_reads_root_target() {
        let root = tempdir().expect("root");
        write_file(root.path(), "etc/b", "inside");
        make_link(root.path(), "etc/a", "/etc/b");

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        assert_eq!(view.read_to_string("/etc/a").expect("read"), "inside");
        assert_eq!(view.read_bytes("/etc/a").expect("read"), b"inside");
        assert!(view.exists("/etc/a"));
        assert!(view.metadata("/etc/a").expect("lstat").is_symlink);
        assert_eq!(view.read_link("/etc/a").expect("readlink"), "/etc/b");
    }

    #[cfg(unix)]
    #[test]
    fn relative_symlink_cannot_escape_root() {
        let root = tempdir().expect("root");
        // `deep` has enough `..` to climb from any temporary directory up to the host `/`.
        let deep = format!("{}etc/passwd", "../".repeat(64));
        make_link(root.path(), "etc/short", "../../../../etc/passwd");
        make_link(root.path(), "etc/deep", &deep);

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        // Without `<root>/etc/passwd`, nothing is read: the host file is never reached.
        for path in ["/etc/short", "/etc/deep"] {
            assert!(
                matches!(view.read_to_string(path), Err(SystemError::NotFound(_))),
                "{path}"
            );
            assert!(!view.exists(path), "{path}");
        }

        // `..` stops at the root, exactly as the booted image would see it.
        write_file(root.path(), "etc/passwd", "image-passwd");
        for path in ["/etc/short", "/etc/deep"] {
            assert_eq!(view.read_to_string(path).expect("read"), "image-passwd");
        }
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_absolute_symlink_directory_is_confined() {
        let host = tempdir().expect("host dir");
        write_file(host.path(), "secret.txt", "HOST-SECRET");
        let root = tempdir().expect("root");
        write_file(root.path(), "real/conf/app.conf", "inside");
        make_link(root.path(), "etc/app", "/real/conf");
        make_link(root.path(), "etc/hostdir", host.path());

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        assert_eq!(
            view.read_to_string("/etc/app/app.conf").expect("read"),
            "inside"
        );
        let names: Vec<String> = view
            .read_dir("/etc/app")
            .expect("read_dir")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["app.conf".to_string()]);
        assert!(
            view.metadata("/etc/app/app.conf")
                .expect("metadata")
                .is_file
        );

        assert!(matches!(
            view.read_to_string("/etc/hostdir/secret.txt"),
            Err(SystemError::NotFound(_))
        ));
        assert!(matches!(
            view.read_dir("/etc/hostdir"),
            Err(SystemError::NotFound(_))
        ));
        assert!(matches!(
            view.metadata("/etc/hostdir/secret.txt"),
            Err(SystemError::NotFound(_))
        ));
        assert!(!view.exists("/etc/hostdir/secret.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loops_fail_cleanly() {
        let root = tempdir().expect("root");
        make_link(root.path(), "a", "b");
        make_link(root.path(), "b", "a");
        make_link(root.path(), "etc/passwd", "/etc/passwd");

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        for path in ["/a", "/b", "/a/child", "/etc/passwd"] {
            assert!(
                matches!(view.read_to_string(path), Err(SystemError::SymlinkLoop(_))),
                "{path}"
            );
            assert!(!view.exists(path), "{path}");
        }
        assert!(matches!(
            view.read_dir("/a"),
            Err(SystemError::SymlinkLoop(_))
        ));
        // `lstat` and `readlink` still see the link itself.
        assert!(view.metadata("/a").expect("lstat").is_symlink);
        assert_eq!(view.read_link("/a").expect("readlink"), "b");
    }

    #[cfg(unix)]
    fn make_link_chain(root: &Path, prefix: &str, len: usize) {
        for i in 0..len {
            let next = if i + 1 == len {
                "target".to_string()
            } else {
                format!("{prefix}{}", i + 1)
            };
            make_link(root, &format!("{prefix}{i}"), next);
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hop_limit_is_explicit() {
        let root = tempdir().expect("root");
        write_file(root.path(), "target", "end");
        make_link_chain(root.path(), "ok", MAX_SYMLINK_HOPS);
        make_link_chain(root.path(), "ko", MAX_SYMLINK_HOPS + 1);

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        assert_eq!(view.read_to_string("/ok0").expect("40 hops"), "end");
        assert!(matches!(
            view.read_to_string("/ko0"),
            Err(SystemError::SymlinkLoop(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn walk_never_traverses_symlinks_out_of_root() {
        let host = tempdir().expect("host dir");
        write_file(host.path(), "secret.txt", "HOST-SECRET");
        let root = tempdir().expect("root");
        write_file(root.path(), "usr/bin/tool", "bin");
        make_link(root.path(), "hostdir", host.path());
        make_link(root.path(), "bin", "usr/bin");

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        let full = view.walk_files(&["/"], &[]).expect("walk");
        let files: Vec<&str> = full.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(files, vec!["/usr/bin/tool"]);
        assert!(full.unreadable_paths.is_empty());

        // A walk root that is itself a symlink is resolved inside the root.
        let via_host_link = view.walk_files(&["/hostdir"], &[]).expect("walk");
        assert!(via_host_link.files.is_empty());
        let via_bin = view.walk_files(&["/bin"], &[]).expect("walk");
        let bin_files: Vec<&str> = via_bin.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(bin_files, vec!["/bin/tool"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_overlay_pointing_outside_root_is_never_loaded() {
        let host = tempdir().expect("host dir");
        write_file(
            host.path(),
            "meta.toml",
            "[files.\"/etc/sudoers\"]\nunreadable = true\n",
        );
        let root = tempdir().expect("root");
        write_file(root.path(), "etc/sudoers", "root ALL=(ALL) ALL\n");
        make_link(
            root.path(),
            FIXTURE_META_FILE,
            host.path().join("meta.toml"),
        );

        let view = RootFsSystemView::from_root(root.path()).expect("root view");
        assert!(view.overlay.is_none());
        assert!(view.read_to_string("/etc/sudoers").is_ok());

        // Even with the explicit opt-in, the overlay is resolved inside the root: the host file
        // it points to is never loaded.
        assert!(matches!(
            view.with_fixture_meta(),
            Err(ManisError::Config(_))
        ));
    }
}
