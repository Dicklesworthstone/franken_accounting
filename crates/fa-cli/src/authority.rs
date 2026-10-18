//! Authority fixed by an MCP host's trusted launch configuration (fa-23r).
//!
//! This is an in-process binding, not an authenticated operator or a bearer
//! token. There is deliberately no wire decoder, request constructor, or
//! authority-bearing CLI flag. The ordinary CLI remains the embedded-owner
//! posture; a bound host must use the typed entrypoint for every command.

use std::path::{Component, Path, PathBuf};

use fa_model::principal_vid;
/// The holder token an issued capability is presented with (fa-v62), for
/// hosts that bind a session to one (`fa-mcp --token`).
pub use fa_policy::CapabilityToken;
use fa_policy::{Capability, Op, Profile};
use fgdb_types::VId;

use crate::json::{Json, obj, s};

/// The two launch templates supported before journaled issuance lands.
/// Preparer is a bounded Human template; it is not an unrestricted Human
/// or System profile. An explicit grant list selects from the ceiling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LaunchProfile {
    #[default]
    Agent,
    Preparer,
}

impl LaunchProfile {
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "agent" => Some(Self::Agent),
            "preparer" => Some(Self::Preparer),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Preparer => "preparer",
        }
    }

    #[must_use]
    pub fn ceiling(self) -> &'static [Op] {
        match self {
            Self::Agent => &[
                Op::Read,
                Op::Post,
                Op::Verify,
                Op::Reconcile,
                Op::Produce,
                Op::PartialView,
            ],
            Self::Preparer => &[
                Op::Read,
                Op::Post,
                Op::PostSoftclosed,
                Op::Verify,
                Op::Reconcile,
                Op::Produce,
                Op::PartialView,
            ],
        }
    }

    fn kernel_profile(self) -> Profile {
        match self {
            Self::Agent => Profile::Agent,
            Self::Preparer => Profile::Human,
        }
    }
}

/// One principal, book, key path and capability for the host's lifetime.
/// Paths are fixed against the launch working directory, so a tool's file
/// context cannot change which book or key file is opened.
#[derive(Clone, Debug)]
pub struct LaunchAuthority {
    book: PathBuf,
    keys: Option<PathBuf>,
    files: Option<PathBuf>,
    principal: String,
    profile: LaunchProfile,
    capability: Capability,
    /// The issued capability's commitment when the session is bound to a
    /// holder's token (`fa-mcp --token`, bead fa-v62), not to a template.
    issued: Option<[u8; 32]>,
    /// That token, which a session presents to the book's fad (fa-r3q).
    token: Option<CapabilityToken>,
}

impl LaunchAuthority {
    /// With no explicit grants the template holds read/post/verify. A
    /// nonempty grant list is the complete requested op set, bounded by the
    /// template ceiling; it never silently adds omitted operations.
    pub fn new(
        book: PathBuf,
        keys: Option<PathBuf>,
        principal: impl Into<String>,
        profile: LaunchProfile,
        grants: &[&str],
    ) -> Result<Self, String> {
        let principal = principal.into();
        if principal.is_empty() || principal.trim() != principal || principal.len() > 256 {
            return Err(
                "the launch principal must be 1..=256 bytes without surrounding whitespace".into(),
            );
        }
        let ops = if grants.is_empty() {
            vec![Op::Read, Op::Post, Op::Verify]
        } else {
            grants
                .iter()
                .map(|name| {
                    Op::from_name(name)
                        .ok_or_else(|| format!("unknown launch capability op `{name}`"))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        for op in &ops {
            if !profile.ceiling().contains(op) {
                return Err(format!(
                    "launch profile `{}` cannot hold `{op}`; grants must stay within its operation ceiling",
                    profile.name()
                ));
            }
        }
        let holder = principal_vid(&principal);
        let capability = Capability::new(holder, profile.kernel_profile(), &ops, holder)
            .map_err(|e| format!("launch capability: {e}"))?;
        Ok(Self {
            book: launch_path(book, "book")?,
            keys: keys.map(|path| launch_path(path, "keys")).transpose()?,
            files: None,
            principal,
            profile,
            capability,
            issued: None,
            token: None,
        })
    }

    /// A session bound to a holder's issued token (plan §14.2, bead fa-v62):
    /// the token's principal, its journaled capability verbatim (so its
    /// ceilings, scope caveats and expiry hold), and the profile it was issued
    /// under. The token's secret has already proven possession
    /// ([`fa_policy::CapabilityToken`] refuses a mismatched one), and the
    /// kernel admits the capability only against its journaled issuance
    /// (FA-REF-156), so an altered or never-issued token reaches nothing.
    pub fn from_token(
        book: PathBuf,
        keys: Option<PathBuf>,
        token: &CapabilityToken,
    ) -> Result<Self, String> {
        let capability = token.capability().clone();
        let profile = match capability.profile() {
            Profile::Agent => LaunchProfile::Agent,
            Profile::Human => LaunchProfile::Preparer,
            Profile::System => {
                return Err("a System-profile capability never binds an MCP session".into());
            }
        };
        // An MCP session never holds more than a launch template's ceiling,
        // however the token was issued: approval, close and issuance stay
        // with the operator.
        if let Some(op) = capability
            .ops()
            .iter()
            .find(|op| !profile.ceiling().contains(op))
        {
            return Err(format!(
                "the token grants `{op}`, beyond the {} session ceiling; issue the MCP holder a token within it",
                profile.name()
            ));
        }
        let issued = capability
            .commitment()
            .map_err(|e| format!("token capability: {e}"))?;
        Ok(Self {
            book: launch_path(book, "book")?,
            keys: keys.map(|path| launch_path(path, "keys")).transpose()?,
            files: None,
            principal: token.principal().to_string(),
            profile,
            capability,
            issued: Some(issued),
            token: Some(token.clone()),
        })
    }

    /// The issued capability's commitment when bound to a token.
    #[must_use]
    pub fn issued(&self) -> Option<[u8; 32]> {
        self.issued
    }

    /// The token this session is bound to, if any.
    #[must_use]
    pub fn token(&self) -> Option<&CapabilityToken> {
        self.token.as_ref()
    }

    /// Attach an optional launch filesystem root (`--files <dir>`). When set,
    /// the directory must exist at launch and is canonicalized once; caller
    /// path arguments are confined to this directory with no `..`, symlinks,
    /// or absolute escapes.
    pub fn with_files(mut self, files: Option<PathBuf>) -> Result<Self, String> {
        self.files = match files {
            None => None,
            Some(path) => Some(launch_files_root(path)?),
        };
        Ok(self)
    }

    #[must_use]
    pub fn book(&self) -> &Path {
        &self.book
    }

    #[must_use]
    pub fn keys(&self) -> Option<&Path> {
        self.keys.as_deref()
    }

    #[must_use]
    pub fn files(&self) -> Option<&Path> {
        self.files.as_deref()
    }

    /// Resolve a caller-supplied relative path under the launch `--files`
    /// root, rejecting absolute paths, `..` traversal, option-shaped strings,
    /// and any symlink component along the path.
    pub fn resolve_in_files_root(
        &self,
        raw: &str,
        allow_missing_leaf: bool,
    ) -> Result<PathBuf, String> {
        let Some(root) = self.files.as_deref() else {
            return Err(
                "no --files launch root is configured; supply inline content instead".into(),
            );
        };
        if raw.is_empty() || raw == "-" || raw.starts_with('-') {
            return Err(format!(
                "path `{raw}` must be a non-empty relative path inside the --files launch root"
            ));
        }
        let rel = Path::new(raw);
        if rel.is_absolute() {
            return Err(format!(
                "absolute path `{raw}` is forbidden; paths must be relative to the --files launch root"
            ));
        }
        let mut normal_segments = Vec::new();
        for component in rel.components() {
            match component {
                Component::Normal(seg) => {
                    if seg.is_empty() {
                        return Err(format!("invalid empty path segment in `{raw}`"));
                    }
                    normal_segments.push(seg);
                }
                Component::ParentDir => {
                    return Err(format!(
                        "parent traversal `..` in `{raw}` is forbidden under --files"
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(format!(
                        "absolute path `{raw}` is forbidden; paths must be relative to the --files launch root"
                    ));
                }
                Component::CurDir => {}
            }
        }
        if normal_segments.is_empty() {
            return Err(format!(
                "`{raw}` does not name a file inside the --files launch root"
            ));
        }
        let mut cur = root.to_path_buf();
        let total = normal_segments.len();
        for (idx, seg) in normal_segments.into_iter().enumerate() {
            let is_last = idx + 1 == total;
            cur.push(seg);
            match std::fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(format!(
                            "symlink component in `{raw}` is forbidden under --files"
                        ));
                    }
                    if !is_last && !meta.is_dir() {
                        return Err(format!(
                            "intermediate component in `{raw}` is not a directory under --files"
                        ));
                    }
                    if is_last && meta.is_dir() {
                        return Err(format!(
                            "`{raw}` names a directory, not a file, under --files"
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if is_last && allow_missing_leaf {
                        break;
                    }
                    return Err(format!(
                        "`{raw}` does not exist under the --files launch root: {e}"
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "cannot inspect `{raw}` under the --files launch root: {e}"
                    ));
                }
            }
        }
        if !cur.starts_with(root) || cur == root || cur.to_str().is_none() {
            return Err(format!("`{raw}` escapes the --files launch root"));
        }
        Ok(cur)
    }

    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    #[must_use]
    pub fn principal_vid(&self) -> VId {
        self.capability.holder()
    }

    #[must_use]
    pub fn profile(&self) -> LaunchProfile {
        self.profile
    }

    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    #[must_use]
    pub fn envelope_json(&self) -> Json {
        obj(vec![
            (
                "posture",
                s(if self.issued.is_some() {
                    "issued-token"
                } else {
                    "mcp-launch-config"
                }),
            ),
            ("principal", s(&self.principal)),
            ("profile", s(self.profile.name())),
            (
                "ops",
                Json::Arr(
                    self.capability
                        .ops()
                        .iter()
                        .map(|op| s(op.name()))
                        .collect(),
                ),
            ),
        ])
    }
}

fn launch_path(path: PathBuf, field: &str) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err(format!("a launch {field} path is required"));
    }
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|e| format!("launch working directory: {e}"))?
            .join(path)
    };
    if path.to_str().is_none() {
        return Err(format!("the launch {field} path must be UTF-8"));
    }
    Ok(path)
}

/// Validate and canonicalize a daemon or launch `--files-root` / `--files`
/// containment directory (`fa-udti`, `fa-yha`). The path must exist, must not
/// be a symlink, and must be a directory.
pub fn validate_files_root(path: PathBuf) -> Result<PathBuf, String> {
    launch_files_root(path)
}

/// Resolve a caller-supplied path against the daemon's `--files-root` (`root`),
/// rejecting `..` traversal, symlinks, paths inside `book_dir`, and absolute
/// paths outside `root` (`fa-udti`).
pub fn resolve_in_daemon_files_root(
    root: &Path,
    book_dir: &Path,
    raw: &str,
    allow_missing_leaf: bool,
) -> Result<PathBuf, String> {
    if raw.is_empty() || raw == "-" || raw.starts_with('-') {
        return Err(format!(
            "path `{raw}` must name a file inside --files-root `{}`",
            root.display()
        ));
    }
    let candidate = Path::new(raw);
    for component in candidate.components() {
        if matches!(component, Component::ParentDir) {
            return Err(format!(
                "parent traversal `..` in `{raw}` is forbidden under --files-root `{}`",
                root.display()
            ));
        }
    }
    let rel = if candidate.is_relative() {
        candidate
    } else if let Ok(stripped) = candidate.strip_prefix(root) {
        stripped
    } else {
        return Err(format!(
            "absolute path `{raw}` is outside --files-root `{}`",
            root.display()
        ));
    };
    let mut normal_segments = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(seg) => {
                if seg.is_empty() {
                    return Err(format!("invalid empty path segment in `{raw}`"));
                }
                normal_segments.push(seg);
            }
            Component::ParentDir => {
                return Err(format!(
                    "parent traversal `..` in `{raw}` is forbidden under --files-root `{}`",
                    root.display()
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "absolute path `{raw}` is outside --files-root `{}`",
                    root.display()
                ));
            }
            Component::CurDir => {}
        }
    }
    if normal_segments.is_empty() {
        return Err(format!(
            "`{raw}` does not name a file inside --files-root `{}`",
            root.display()
        ));
    }
    let canon_book = std::fs::canonicalize(book_dir).unwrap_or_else(|_| book_dir.to_path_buf());
    let mut cur = root.to_path_buf();
    let total = normal_segments.len();
    for (idx, seg) in normal_segments.into_iter().enumerate() {
        let is_last = idx + 1 == total;
        cur.push(seg);
        if cur == canon_book
            || cur.starts_with(&canon_book)
            || cur == book_dir
            || cur.starts_with(book_dir)
        {
            return Err(format!(
                "path `{raw}` resolves inside book directory `{}` and cannot be accessed as a host file",
                book_dir.display()
            ));
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "symlink component in `{raw}` is forbidden under --files-root `{}`",
                        root.display()
                    ));
                }
                if !is_last && !meta.is_dir() {
                    return Err(format!(
                        "intermediate component in `{raw}` is not a directory under --files-root `{}`",
                        root.display()
                    ));
                }
                if is_last && meta.is_dir() {
                    return Err(format!(
                        "`{raw}` names a directory, not a file, under --files-root `{}`",
                        root.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if is_last && allow_missing_leaf {
                    break;
                }
                return Err(format!(
                    "`{raw}` does not exist under --files-root `{}`: {e}",
                    root.display()
                ));
            }
            Err(e) => {
                return Err(format!(
                    "cannot inspect `{raw}` under --files-root `{}`: {e}",
                    root.display()
                ));
            }
        }
    }
    let resolved = if allow_missing_leaf && !cur.exists() {
        let parent = cur
            .parent()
            .ok_or_else(|| format!("`{raw}` has no parent under --files-root"))?;
        let canon_parent = std::fs::canonicalize(parent)
            .map_err(|e| format!("cannot canonicalize parent of `{raw}`: {e}"))?;
        if !canon_parent.starts_with(root)
            || canon_parent == canon_book
            || canon_parent.starts_with(&canon_book)
        {
            return Err(format!("`{raw}` escapes --files-root `{}`", root.display()));
        }
        canon_parent.join(
            cur.file_name()
                .ok_or_else(|| format!("`{raw}` has no file name"))?,
        )
    } else {
        let canon =
            std::fs::canonicalize(&cur).map_err(|e| format!("cannot canonicalize `{raw}`: {e}"))?;
        if !canon.starts_with(root)
            || canon == root
            || canon == canon_book
            || canon.starts_with(&canon_book)
        {
            return Err(format!("`{raw}` escapes --files-root `{}`", root.display()));
        }
        canon
    };
    if resolved.to_str().is_none() {
        return Err(format!("`{raw}` is not valid UTF-8 under --files-root"));
    }
    Ok(resolved)
}

fn launch_files_root(path: PathBuf) -> Result<PathBuf, String> {
    let path = launch_path(path, "files")?;
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| format!("launch files root `{}`: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "launch files root `{}` cannot be a symlink",
            path.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!(
            "launch files root `{}` must be a directory",
            path.display()
        ));
    }
    let canonical = std::fs::canonicalize(&path)
        .map_err(|e| format!("launch files root `{}`: {e}", path.display()))?;
    if canonical.to_str().is_none() {
        return Err("the launch files root path must be UTF-8".into());
    }
    Ok(canonical)
}

/// No fixed op ceiling exists on the ordinary embedded-owner route. Null
/// ops means per-command self-issuance, not an authenticated empty grant.
pub(crate) fn owner_envelope(principal: Option<&str>) -> Json {
    obj(vec![
        ("posture", s("embedded-owner")),
        ("principal", principal.map_or(Json::Null, s)),
        ("profile", s(Profile::Human.name())),
        ("ops", Json::Null),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(profile: LaunchProfile, grants: &[&str]) -> Result<LaunchAuthority, String> {
        LaunchAuthority::new(PathBuf::from("/book"), None, "agent-7", profile, grants)
    }

    #[test]
    fn the_default_template_reaches_the_kernel_as_an_agent() {
        let authority = launch(LaunchProfile::default(), &[]).unwrap();
        assert_eq!(authority.capability().profile(), Profile::Agent);
        assert_eq!(authority.capability().holder(), principal_vid("agent-7"));
        assert_eq!(
            authority
                .capability()
                .ops()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![Op::Read, Op::Post, Op::Verify]
        );
        assert_eq!(
            authority
                .envelope_json()
                .get("profile")
                .and_then(Json::as_str),
            Some("agent")
        );
    }

    #[test]
    fn explicit_grants_are_bounded_and_do_not_add_implicit_authority() {
        for profile in [LaunchProfile::Agent, LaunchProfile::Preparer] {
            for op in Op::ALL {
                let result = launch(profile, &[op.name()]);
                assert_eq!(
                    result.is_ok(),
                    profile.ceiling().contains(&op),
                    "{profile:?} {op}"
                );
            }
        }
        let reader = launch(LaunchProfile::Agent, &["read"]).unwrap();
        assert!(!reader.capability().holds(Op::Post));
        assert!(!reader.capability().holds(Op::Verify));
        assert!(
            launch(LaunchProfile::Agent, &["approve"])
                .unwrap_err()
                .contains("cannot hold")
        );
        assert!(launch(LaunchProfile::Agent, &["post_closed"]).is_err());
        assert!(launch(LaunchProfile::Agent, &["migrate"]).is_err());
        assert!(launch(LaunchProfile::Agent, &["witness"]).is_err());
        assert!(launch(LaunchProfile::Preparer, &["approve"]).is_err());
        assert_eq!(LaunchProfile::from_name("human"), None);
        assert_eq!(LaunchProfile::from_name("system"), None);
    }

    /// fa-v62: a token binds the session to its own journaled capability
    /// (possession caveat included), and never beyond a launch ceiling.
    #[test]
    fn an_issued_token_binds_its_capability_within_the_launch_ceiling() {
        let secret = [9; 32];
        let token = |profile: Profile, ops: &[Op]| {
            let cap = Capability::new(principal_vid("agent-7"), profile, ops, VId(1))
                .unwrap()
                .holder_bound(fa_policy::possession_digest(&secret));
            CapabilityToken::new("agent-7", cap, secret).unwrap()
        };
        let agent = token(Profile::Agent, &[Op::Read, Op::Post]);
        let bound = LaunchAuthority::from_token(PathBuf::from("/book"), None, &agent).unwrap();
        assert_eq!(bound.capability(), agent.capability());
        assert_eq!(bound.principal_vid(), principal_vid("agent-7"));
        assert_eq!(
            bound.issued(),
            Some(agent.capability().commitment().unwrap())
        );
        let envelope = bound.envelope_json();
        assert_eq!(
            envelope.get("posture").and_then(Json::as_str),
            Some("issued-token")
        );
        assert_eq!(
            envelope.get("profile").and_then(Json::as_str),
            Some("agent")
        );
        let preparer = token(Profile::Human, &[Op::Read, Op::PostSoftclosed]);
        let bound = LaunchAuthority::from_token(PathBuf::from("/book"), None, &preparer).unwrap();
        assert_eq!(
            bound.envelope_json().get("profile").and_then(Json::as_str),
            Some("preparer")
        );
        let approver = token(Profile::Human, &[Op::Read, Op::Approve]);
        let refused = LaunchAuthority::from_token(PathBuf::from("/book"), None, &approver);
        assert!(refused.unwrap_err().contains("`approve`"));
        let system = token(Profile::System, &[Op::Read]);
        assert!(LaunchAuthority::from_token(PathBuf::from("/book"), None, &system).is_err());
    }

    #[test]
    fn files_root_resolver_confines_paths_and_rejects_escapes() {
        let base = std::env::temp_dir().join(format!(
            "fa-authority-files-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let root = base.join("files");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).expect("create files root");
        let doc = root.join("invoice.txt");
        std::fs::write(&doc, b"invoice").expect("write invoice");
        let nested = sub.join("nested.txt");
        std::fs::write(&nested, b"nested").expect("write nested");
        let outside = base.join("outside.txt");
        std::fs::write(&outside, b"outside").expect("write outside");

        let no_files = launch(LaunchProfile::Agent, &[]).unwrap();
        assert!(
            no_files
                .resolve_in_files_root("invoice.txt", false)
                .is_err()
        );

        let authority = launch(LaunchProfile::Agent, &[])
            .unwrap()
            .with_files(Some(root.clone()))
            .expect("with_files");
        let canon_root = std::fs::canonicalize(&root).unwrap();
        assert_eq!(authority.files(), Some(canon_root.as_path()));

        // Positive: in-root existing files and missing output leaf.
        assert_eq!(
            authority
                .resolve_in_files_root("invoice.txt", false)
                .expect("in-root file"),
            canon_root.join("invoice.txt")
        );
        assert_eq!(
            authority
                .resolve_in_files_root("sub/nested.txt", false)
                .expect("in-root nested file"),
            canon_root.join("sub").join("nested.txt")
        );
        assert_eq!(
            authority
                .resolve_in_files_root("close.plan", true)
                .expect("in-root output leaf"),
            canon_root.join("close.plan")
        );
        assert!(
            authority
                .resolve_in_files_root("missing.txt", false)
                .is_err()
        );

        // Planted negatives: absolute path, .. escape, option-shaped, directory.
        assert!(
            authority
                .resolve_in_files_root(outside.to_str().unwrap(), false)
                .unwrap_err()
                .contains("absolute path")
        );
        assert!(
            authority
                .resolve_in_files_root(canon_root.join("invoice.txt").to_str().unwrap(), false)
                .unwrap_err()
                .contains("absolute path")
        );
        assert!(
            authority
                .resolve_in_files_root("../outside.txt", false)
                .unwrap_err()
                .contains("..")
        );
        assert!(
            authority
                .resolve_in_files_root("sub/../../outside.txt", false)
                .unwrap_err()
                .contains("..")
        );
        assert!(authority.resolve_in_files_root("-", false).is_err());
        assert!(authority.resolve_in_files_root("--flag", false).is_err());
        assert!(authority.resolve_in_files_root(".", false).is_err());
        assert!(authority.resolve_in_files_root("sub", false).is_err());

        #[cfg(unix)]
        {
            let link = root.join("escape-link.txt");
            std::os::unix::fs::symlink(&outside, &link).expect("create symlink");
            assert!(
                authority
                    .resolve_in_files_root("escape-link.txt", false)
                    .unwrap_err()
                    .contains("symlink")
            );
            assert!(
                authority
                    .resolve_in_files_root("escape-link.txt", true)
                    .unwrap_err()
                    .contains("symlink")
            );
            let dir_link = root.join("dir-link");
            std::os::unix::fs::symlink(&base, &dir_link).expect("create dir symlink");
            assert!(
                authority
                    .resolve_in_files_root("dir-link/outside.txt", false)
                    .unwrap_err()
                    .contains("symlink")
            );
        }
    }
}
