//! System inspection abstraction enabling deterministic offline testing via `--root`.

pub mod rootfs;

use crate::error::SystemError;

pub use rootfs::RootFsSystemView;

/// File metadata exposed by [`SystemView`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// Full Unix mode bits (file type + special bits + rwx permissions, e.g. `0o104755` or `0o4755`).
    pub mode: u32,
    /// Owner numeric UID.
    pub uid: u32,
    /// Owner numeric GID.
    pub gid: u32,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
}

impl FileMeta {
    /// Returns the lower 12 permission + special mode bits (`0o7777`).
    pub const fn perm_bits(&self) -> u32 {
        self.mode & 0o7777
    }

    /// Returns `true` when the SUID bit (`0o4000`) is set.
    pub const fn is_suid(&self) -> bool {
        (self.mode & 0o4000) != 0
    }

    /// Returns `true` when the SGID bit (`0o2000`) is set.
    pub const fn is_sgid(&self) -> bool {
        (self.mode & 0o2000) != 0
    }

    /// Returns `true` when the world-writable bit (`0o0002`) is set.
    pub const fn is_world_writable(&self) -> bool {
        (self.mode & 0o0002) != 0
    }

    /// Returns `true` when the sticky bit (`0o1000`) is set.
    pub const fn has_sticky_bit(&self) -> bool {
        (self.mode & 0o1000) != 0
    }
}

/// Deterministic directory entry returned by [`SystemView::read_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    /// Entry file name (basename only).
    pub name: String,
    /// Normalized virtual absolute path (e.g. `/etc/sudoers.d/local`).
    pub path: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// A single regular file discovered during [`SystemView::walk_files`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkedFile {
    /// Normalized virtual absolute path (e.g. `/usr/bin/passwd`).
    pub path: String,
    pub meta: FileMeta,
}

/// Result of a deterministic recursive file walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkReport {
    /// Discovered regular files, sorted lexicographically by virtual path.
    pub files: Vec<WalkedFile>,
    /// Discovered directories (excluding root `/`), sorted lexicographically by virtual path.
    pub dirs: Vec<WalkedFile>,
    /// Virtual paths that could not be inspected due to permissions or I/O errors.
    pub unreadable_paths: Vec<String>,
}

/// Read-only abstraction over a Linux host filesystem or `--root` fixture tree.
pub trait SystemView {
    /// Human-readable display root (`/` for live host, or the `--root` path).
    fn display_root(&self) -> &str;

    /// Reads a UTF-8 text file at the virtual path (e.g. `/proc/mounts`).
    fn read_to_string(&self, path: &str) -> Result<String, SystemError>;

    /// Reads raw bytes from a file at the virtual path (e.g. `/proc/config.gz`).
    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, SystemError>;

    /// Returns `true` if a file or directory exists at the virtual path.
    fn exists(&self, path: &str) -> bool;

    /// Reads file metadata (mode, uid, gid, file type) without following symlinks.
    fn metadata(&self, path: &str) -> Result<FileMeta, SystemError>;

    /// Reads the target of a symbolic link at the virtual path (e.g. `/dev/null` for a masked unit).
    fn read_link(&self, path: &str) -> Result<String, SystemError>;

    /// Lists entries in a directory sorted lexicographically by name.
    fn read_dir(&self, path: &str) -> Result<Vec<DirEntryInfo>, SystemError>;

    /// Recursively walks regular files under `roots`, skipping any virtual directory in `skip_dirs`.
    ///
    /// Symlinks are never followed. Unreadable files or directories are recorded in
    /// [`WalkReport::unreadable_paths`] rather than silently discarded.
    fn walk_files(&self, roots: &[&str], skip_dirs: &[&str]) -> Result<WalkReport, SystemError>;

    /// Returns the target kernel release string (e.g. `6.8.0-45-generic`).
    fn kernel_release(&self) -> Result<String, SystemError>;
}
