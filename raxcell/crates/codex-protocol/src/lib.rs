use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

const PROTECTED_METADATA_GIT_PATH_NAME: &str = ".git";
const PROTECTED_METADATA_AGENTS_PATH_NAME: &str = ".agents";
const PROTECTED_METADATA_CODEX_PATH_NAME: &str = ".codex";

/// Top-level workspace metadata paths that stay protected under writable roots.
pub const PROTECTED_METADATA_PATH_NAMES: [&str; 3] = [
    PROTECTED_METADATA_GIT_PATH_NAME,
    PROTECTED_METADATA_AGENTS_PATH_NAME,
    PROTECTED_METADATA_CODEX_PATH_NAME,
];

/// Returns true when a path basename is one of the protected workspace metadata names.
pub fn is_protected_metadata_name(name: impl AsRef<str>) -> bool {
    PROTECTED_METADATA_PATH_NAMES.contains(&name.as_ref())
}

/// Returns true for protected metadata names Codex treats as directories.
pub fn is_protected_metadata_directory_name(name: impl AsRef<str>) -> bool {
    matches!(
        name.as_ref(),
        PROTECTED_METADATA_AGENTS_PATH_NAME | PROTECTED_METADATA_CODEX_PATH_NAME
    )
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkSandboxPolicy {
    #[default]
    Restricted,
    Enabled,
}

impl NetworkSandboxPolicy {
    pub fn is_enabled(self) -> bool {
        matches!(self, NetworkSandboxPolicy::Enabled)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileSystemAccessMode {
    Read,
    Write,
    #[serde(alias = "none")]
    Deny,
}

impl FileSystemAccessMode {
    pub fn can_read(self) -> bool {
        !matches!(self, FileSystemAccessMode::Deny)
    }

    pub fn can_write(self) -> bool {
        matches!(self, FileSystemAccessMode::Write)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileSystemSpecialPath {
    Root,
    Minimal,
    #[serde(alias = "current_working_directory")]
    ProjectRoots {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subpath: Option<PathBuf>,
    },
    Tmpdir,
    SlashTmp,
    Unknown {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subpath: Option<PathBuf>,
    },
}

impl FileSystemSpecialPath {
    pub fn project_roots(subpath: Option<PathBuf>) -> Self {
        Self::ProjectRoots { subpath }
    }

    pub fn unknown(path: impl Into<String>, subpath: Option<PathBuf>) -> Self {
        Self::Unknown {
            path: path.into(),
            subpath,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FileSystemPath {
    Path { path: PathBuf },
    GlobPattern { pattern: String },
    Special { value: FileSystemSpecialPath },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileSystemSandboxEntry {
    pub path: FileSystemPath,
    pub access: FileSystemAccessMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileSystemSandboxKind {
    #[default]
    Restricted,
    Unrestricted,
    ExternalSandbox,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSystemSandboxPolicy {
    pub kind: FileSystemSandboxKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob_scan_max_depth: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<FileSystemSandboxEntry>,
}

impl Default for FileSystemSandboxPolicy {
    fn default() -> Self {
        Self::read_only()
    }
}

impl FileSystemSandboxPolicy {
    pub fn read_only() -> Self {
        Self::restricted(vec![FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        }])
    }

    pub fn unrestricted() -> Self {
        Self {
            kind: FileSystemSandboxKind::Unrestricted,
            glob_scan_max_depth: None,
            entries: Vec::new(),
        }
    }

    pub fn external_sandbox() -> Self {
        Self {
            kind: FileSystemSandboxKind::ExternalSandbox,
            glob_scan_max_depth: None,
            entries: Vec::new(),
        }
    }

    pub fn restricted(entries: Vec<FileSystemSandboxEntry>) -> Self {
        Self {
            kind: FileSystemSandboxKind::Restricted,
            glob_scan_max_depth: None,
            entries,
        }
    }

    pub fn can_read_path(&self, path: impl AsRef<Path>) -> bool {
        if self.has_unsupported_access_entries() {
            return false;
        }
        self.resolve_access(path.as_ref()).can_read()
    }

    pub fn can_write_path(&self, path: impl AsRef<Path>) -> bool {
        if self.has_unsupported_access_entries() {
            return false;
        }
        let path = path.as_ref();
        if !self.resolve_access(path).can_write() {
            return false;
        }
        if self.has_full_disk_write_access() {
            return true;
        }
        !self.is_metadata_write_denied(path)
    }

    pub fn has_full_disk_read_access(&self) -> bool {
        if matches!(
            self.kind,
            FileSystemSandboxKind::Unrestricted | FileSystemSandboxKind::ExternalSandbox
        ) {
            return true;
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.access == FileSystemAccessMode::Deny)
        {
            return false;
        }
        self.has_root_access(FileSystemAccessMode::can_read)
    }

    pub fn has_full_disk_write_access(&self) -> bool {
        if matches!(
            self.kind,
            FileSystemSandboxKind::Unrestricted | FileSystemSandboxKind::ExternalSandbox
        ) {
            return true;
        }
        if self.has_write_narrowing_entries() {
            return false;
        }
        self.has_root_access(FileSystemAccessMode::can_write)
    }

    fn has_root_access(&self, predicate: impl Fn(FileSystemAccessMode) -> bool) -> bool {
        matches!(self.kind, FileSystemSandboxKind::Restricted)
            && self.entries.iter().any(|entry| {
                matches!(
                    &entry.path,
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root
                    } if predicate(entry.access)
                )
            })
    }

    fn resolve_access(&self, path: &Path) -> FileSystemAccessMode {
        match self.kind {
            FileSystemSandboxKind::Unrestricted | FileSystemSandboxKind::ExternalSandbox => {
                FileSystemAccessMode::Write
            }
            FileSystemSandboxKind::Restricted => self
                .entries
                .iter()
                .filter_map(|entry| {
                    let prefix_len = match &entry.path {
                        FileSystemPath::Path { path: entry_path } => path
                            .starts_with(entry_path)
                            .then(|| entry_path.components().count()),
                        FileSystemPath::Special {
                            value: FileSystemSpecialPath::Root,
                        } => Some(0),
                        FileSystemPath::GlobPattern { .. } | FileSystemPath::Special { .. } => None,
                    }?;
                    Some((prefix_len, entry.access))
                })
                .max_by_key(|(len, access)| (*len, *access))
                .map(|(_, access)| access)
                .unwrap_or(FileSystemAccessMode::Deny),
        }
    }

    fn is_metadata_write_denied(&self, path: &Path) -> bool {
        let metadata_root = self
            .entries
            .iter()
            .filter(|entry| entry.access.can_write())
            .filter_map(|entry| entry.path.as_path())
            .find_map(|writable_root| {
                let relative = path.strip_prefix(writable_root).ok()?;
                let metadata_name = relative.components().next()?.as_os_str().to_str()?;
                if is_protected_metadata_name(metadata_name) {
                    Some(writable_root.join(metadata_name))
                } else {
                    None
                }
            });

        metadata_root.is_some_and(|metadata_root| {
            !self.entries.iter().any(|entry| {
                entry.access.can_write()
                    && entry.path.as_path().is_some_and(|entry_path| {
                        path.starts_with(entry_path) && entry_path.starts_with(&metadata_root)
                    })
            })
        })
    }

    fn has_unsupported_access_entries(&self) -> bool {
        matches!(self.kind, FileSystemSandboxKind::Restricted)
            && self.entries.iter().any(|entry| {
                matches!(entry.path, FileSystemPath::GlobPattern { .. })
                    || matches!(
                        entry.path,
                        FileSystemPath::Special { .. } if !entry.path.is_root_special_path()
                    )
            })
    }

    fn has_write_narrowing_entries(&self) -> bool {
        self.entries.iter().any(|entry| match entry.access {
            FileSystemAccessMode::Write => false,
            FileSystemAccessMode::Deny => true,
            FileSystemAccessMode::Read => {
                entry.path.narrows_root_write()
                    && !self.entries.iter().any(|candidate| {
                        candidate.access.can_write() && candidate.path == entry.path
                    })
            }
        })
    }
}

impl FileSystemPath {
    fn as_path(&self) -> Option<&Path> {
        match self {
            FileSystemPath::Path { path } => Some(path.as_path()),
            FileSystemPath::GlobPattern { .. } | FileSystemPath::Special { .. } => None,
        }
    }

    fn is_root_special_path(&self) -> bool {
        matches!(
            self,
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root
            }
        )
    }

    fn narrows_root_write(&self) -> bool {
        matches!(
            self,
            FileSystemPath::Path { .. } | FileSystemPath::GlobPattern { .. }
        ) || matches!(self, FileSystemPath::Special { .. } if !self.is_root_special_path())
    }
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FileSystemPermissions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<FileSystemSandboxEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob_scan_max_depth: Option<NonZeroUsize>,
}

impl FileSystemPermissions {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.glob_scan_max_depth.is_none()
    }
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NetworkPermissions {
    pub enabled: Option<bool>,
}

impl NetworkPermissions {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
    }
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct AdditionalPermissionProfile {
    pub network: Option<NetworkPermissions>,
    pub file_system: Option<FileSystemPermissions>,
}

impl AdditionalPermissionProfile {
    pub fn is_empty(&self) -> bool {
        self.network.is_none() && self.file_system.is_none()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ManagedFileSystemPermissions {
    Restricted {
        entries: Vec<FileSystemSandboxEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        glob_scan_max_depth: Option<NonZeroUsize>,
    },
    Unrestricted,
}

impl ManagedFileSystemPermissions {
    pub fn to_sandbox_policy(&self) -> FileSystemSandboxPolicy {
        match self {
            Self::Restricted {
                entries,
                glob_scan_max_depth,
            } => FileSystemSandboxPolicy {
                kind: FileSystemSandboxKind::Restricted,
                glob_scan_max_depth: glob_scan_max_depth.map(usize::from),
                entries: entries.clone(),
            },
            Self::Unrestricted => FileSystemSandboxPolicy::unrestricted(),
        }
    }
}

impl From<&FileSystemSandboxPolicy> for ManagedFileSystemPermissions {
    fn from(value: &FileSystemSandboxPolicy) -> Self {
        match value.kind {
            FileSystemSandboxKind::Restricted => Self::Restricted {
                entries: value.entries.clone(),
                glob_scan_max_depth: value.glob_scan_max_depth.and_then(NonZeroUsize::new),
            },
            FileSystemSandboxKind::Unrestricted => Self::Unrestricted,
            FileSystemSandboxKind::ExternalSandbox => {
                unreachable!(
                    "external filesystem policies are represented by PermissionProfile::External"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PermissionProfile {
    Managed {
        file_system: ManagedFileSystemPermissions,
        network: NetworkSandboxPolicy,
    },
    Disabled,
    External {
        network: NetworkSandboxPolicy,
    },
}

impl Default for PermissionProfile {
    fn default() -> Self {
        Self::Managed {
            file_system: ManagedFileSystemPermissions::Restricted {
                entries: Vec::new(),
                glob_scan_max_depth: None,
            },
            network: NetworkSandboxPolicy::Restricted,
        }
    }
}

impl PermissionProfile {
    pub fn read_only() -> Self {
        let file_system = FileSystemSandboxPolicy::read_only();
        Self::Managed {
            file_system: ManagedFileSystemPermissions::from(&file_system),
            network: NetworkSandboxPolicy::Restricted,
        }
    }

    pub fn from_runtime_permissions(
        file_system_sandbox_policy: &FileSystemSandboxPolicy,
        network_sandbox_policy: NetworkSandboxPolicy,
    ) -> Self {
        match file_system_sandbox_policy.kind {
            FileSystemSandboxKind::Restricted | FileSystemSandboxKind::Unrestricted => {
                Self::Managed {
                    file_system: ManagedFileSystemPermissions::from(file_system_sandbox_policy),
                    network: network_sandbox_policy,
                }
            }
            FileSystemSandboxKind::ExternalSandbox => Self::External {
                network: network_sandbox_policy,
            },
        }
    }

    pub fn file_system_sandbox_policy(&self) -> FileSystemSandboxPolicy {
        match self {
            Self::Managed { file_system, .. } => file_system.to_sandbox_policy(),
            Self::Disabled => FileSystemSandboxPolicy::unrestricted(),
            Self::External { .. } => FileSystemSandboxPolicy::external_sandbox(),
        }
    }

    pub fn network_sandbox_policy(&self) -> NetworkSandboxPolicy {
        match self {
            Self::Managed { network, .. } | Self::External { network } => *network,
            Self::Disabled => NetworkSandboxPolicy::Enabled,
        }
    }

    pub fn to_runtime_permissions(&self) -> (FileSystemSandboxPolicy, NetworkSandboxPolicy) {
        (
            self.file_system_sandbox_policy(),
            self.network_sandbox_policy(),
        )
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
