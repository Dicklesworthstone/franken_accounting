//! Authority fixed by an MCP host's trusted launch configuration (fa-23r).
//!
//! This is an in-process binding, not an authenticated operator or a bearer
//! token. There is deliberately no wire decoder, request constructor, or
//! authority-bearing CLI flag. The ordinary CLI remains the embedded-owner
//! posture; a bound host must use the typed entrypoint for every command.

use std::path::{Path, PathBuf};

use fa_model::principal_vid;
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
    principal: String,
    profile: LaunchProfile,
    capability: Capability,
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
            principal,
            profile,
            capability,
        })
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
            ("posture", s("mcp-launch-config")),
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
}
