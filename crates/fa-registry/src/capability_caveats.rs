//! `registries/capability_caveats.toml`: the closed operation vocabulary,
//! caveat vocabulary (active header fields, v2 tagged caveats, and dormant
//! planned caveats), and §14.4 profile templates (plan §14.2, §14.4, bead fa-v62).

use std::collections::BTreeSet;

use crate::sod_policy::PROFILES;
use crate::toml::{Table, Value};
use crate::{RegistryError, invalid, load, req_int, req_str};

const CAPABILITY_CAVEATS: &str = include_str!("../../../registries/capability_caveats.toml");
const R: &str = "capability_caveats.toml";

/// One operation in `[[op]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpRow {
    pub tag: u8,
    pub name: String,
    pub agent_forbidden: bool,
    pub system_forbidden: bool,
    pub summary: String,
}

/// How a caveat is encoded in `fa:capability:v1` / v2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaveatEncoding {
    /// Fixed v1 header field (`ops`, `per_leg_ceilings`, `expires_at`).
    Field,
    /// Tagged v2 caveat (`tag = 1..=255`).
    Tagged(u8),
    /// Planned caveat not yet encoded on the wire (`status = "dormant"`).
    Planned,
}

/// Whether a caveat is active in this build or dormant pending a named bead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaveatStatus {
    Live,
    Dormant,
}

/// One caveat row in `[[caveat]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaveatRow {
    pub name: String,
    pub encoding: CaveatEncoding,
    pub status: CaveatStatus,
    pub tracking_bead: Option<String>,
    pub payload_type: String,
    pub attenuation_law: String,
    pub summary: String,
}

/// One profile template in `[[profile]]` (plan §14.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileTemplateRow {
    pub name: String,
    pub base_profile: String,
    pub external: bool,
    pub ops_ceiling: Vec<String>,
    pub default_ops: Vec<String>,
    pub required_caveats: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityCaveats {
    pub ops: Vec<OpRow>,
    pub caveats: Vec<CaveatRow>,
    pub profiles: Vec<ProfileTemplateRow>,
}

fn req_bool(t: &Table, key: &str, what: &str) -> Result<bool, RegistryError> {
    t.get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(R, format!("{what}: missing boolean `{key}`")))
}

fn req_nonempty_str<'a>(t: &'a Table, key: &str, what: &str) -> Result<&'a str, RegistryError> {
    let val =
        req_str(R, t, key).map_err(|_| invalid(R, format!("{what}: missing string `{key}`")))?;
    if val.trim().is_empty() {
        return Err(invalid(R, format!("{what}: `{key}` must not be empty")));
    }
    Ok(val)
}

fn req_str_list(t: &Table, key: &str, what: &str) -> Result<Vec<String>, RegistryError> {
    let arr = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(R, format!("{what}: missing array `{key}`")))?;
    if arr.is_empty() {
        return Err(invalid(R, format!("{what}: `{key}` must not be empty")));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let s = v.as_str().filter(|s| !s.trim().is_empty()).ok_or_else(|| {
            invalid(
                R,
                format!("{what}: `{key}` holds a non-string or empty item"),
            )
        })?;
        if !seen.insert(s) {
            return Err(invalid(
                R,
                format!("{what}: `{key}` lists `{s}` more than once"),
            ));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

impl CapabilityCaveats {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(CAPABILITY_CAVEATS)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let empty = Vec::new();

        // 1. Parse [[op]] in contiguous tag order 0..n.
        let mut ops = Vec::new();
        let mut op_names = BTreeSet::new();
        for (expected_tag, t) in doc.arrays.get("op").unwrap_or(&empty).iter().enumerate() {
            let raw_tag = req_int(R, t, "tag")?;
            let tag = u8::try_from(raw_tag)
                .map_err(|_| invalid(R, format!("op tag {raw_tag} out of u8 range")))?;
            if usize::from(tag) != expected_tag {
                return Err(invalid(
                    R,
                    format!(
                        "[[op]] tags must be contiguous starting at 0; expected {expected_tag}, got {tag}"
                    ),
                ));
            }
            let what = format!("op {tag}");
            let name = req_nonempty_str(t, "name", &what)?.to_string();
            if !op_names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate op `{name}`")));
            }
            let agent_forbidden = req_bool(t, "agent_forbidden", &what)?;
            let system_forbidden = req_bool(t, "system_forbidden", &what)?;
            let summary = req_nonempty_str(t, "summary", &what)?.to_string();
            ops.push(OpRow {
                tag,
                name,
                agent_forbidden,
                system_forbidden,
                summary,
            });
        }
        if ops.is_empty() {
            return Err(invalid(R, "at least one [[op]] row is required"));
        }

        // 2. Parse [[caveat]].
        let mut caveats = Vec::new();
        let mut caveat_names = BTreeSet::new();
        let mut caveat_tags = BTreeSet::new();
        for t in doc.arrays.get("caveat").unwrap_or(&empty) {
            let name = req_nonempty_str(t, "name", "caveat")?.to_string();
            let what = format!("caveat `{name}`");
            if !caveat_names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate caveat `{name}`")));
            }
            let status = match req_nonempty_str(t, "status", &what)? {
                "live" => CaveatStatus::Live,
                "dormant" => CaveatStatus::Dormant,
                other => {
                    return Err(invalid(
                        R,
                        format!("{what}: unknown status `{other}` (expected `live` or `dormant`)"),
                    ));
                }
            };
            let raw_tag = t.get("tag").map(|v| {
                v.as_int()
                    .and_then(|i| u8::try_from(i).ok())
                    .filter(|tag| *tag >= 1)
                    .ok_or_else(|| invalid(R, format!("{what}: `tag` must be in 1..=255")))
            });
            let tag = match raw_tag {
                Some(res) => Some(res?),
                None => None,
            };
            let tracking_bead = match t.get("tracking_bead") {
                Some(v) => {
                    let b = v
                        .as_str()
                        .filter(|s| !s.trim().is_empty())
                        .ok_or_else(|| invalid(R, format!("{what}: invalid `tracking_bead`")))?;
                    Some(b.to_string())
                }
                None => None,
            };
            let encoding = match req_nonempty_str(t, "encoding", &what)? {
                "field" => {
                    if status != CaveatStatus::Live || tag.is_some() || tracking_bead.is_some() {
                        return Err(invalid(
                            R,
                            format!(
                                "{what}: `field` caveats must be `live` without `tag` or `tracking_bead`"
                            ),
                        ));
                    }
                    CaveatEncoding::Field
                }
                "tagged" => {
                    let Some(tag_val) = tag else {
                        return Err(invalid(
                            R,
                            format!("{what}: `tagged` caveats require a `tag` in 1..=255"),
                        ));
                    };
                    if status != CaveatStatus::Live || tracking_bead.is_some() {
                        return Err(invalid(
                            R,
                            format!(
                                "{what}: `tagged` caveats must be `live` without `tracking_bead`"
                            ),
                        ));
                    }
                    if !caveat_tags.insert(tag_val) {
                        return Err(invalid(
                            R,
                            format!("{what}: duplicate caveat tag {tag_val}"),
                        ));
                    }
                    CaveatEncoding::Tagged(tag_val)
                }
                "planned" => {
                    if status != CaveatStatus::Dormant || tag.is_some() || tracking_bead.is_none() {
                        return Err(invalid(
                            R,
                            format!(
                                "{what}: `planned` caveats must be `dormant` with `tracking_bead` and no `tag`"
                            ),
                        ));
                    }
                    CaveatEncoding::Planned
                }
                other => {
                    return Err(invalid(
                        R,
                        format!(
                            "{what}: unknown encoding `{other}` (expected `field`, `tagged`, or `planned`)"
                        ),
                    ));
                }
            };
            let payload_type = req_nonempty_str(t, "payload_type", &what)?.to_string();
            let attenuation_law = req_nonempty_str(t, "attenuation_law", &what)?.to_string();
            let summary = req_nonempty_str(t, "summary", &what)?.to_string();
            caveats.push(CaveatRow {
                name,
                encoding,
                status,
                tracking_bead,
                payload_type,
                attenuation_law,
                summary,
            });
        }
        if caveats.is_empty() {
            return Err(invalid(R, "at least one [[caveat]] row is required"));
        }

        // 3. Parse [[profile]].
        let mut profiles = Vec::new();
        let mut profile_names = BTreeSet::new();
        for t in doc.arrays.get("profile").unwrap_or(&empty) {
            let name = req_nonempty_str(t, "name", "profile")?.to_string();
            let what = format!("profile `{name}`");
            if !profile_names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate profile `{name}`")));
            }
            let base_profile = req_nonempty_str(t, "base_profile", &what)?.to_string();
            if !PROFILES.contains(&base_profile.as_str()) {
                return Err(invalid(
                    R,
                    format!("{what}: unknown base_profile `{base_profile}`"),
                ));
            }
            let external = req_bool(t, "external", &what)?;
            let ops_ceiling = req_str_list(t, "ops_ceiling", &what)?;
            for op_name in &ops_ceiling {
                let Some(op_row) = ops.iter().find(|o| &o.name == op_name) else {
                    return Err(invalid(
                        R,
                        format!("{what}: ops_ceiling cites unknown op `{op_name}`"),
                    ));
                };
                if (base_profile == "Agent" && op_row.agent_forbidden)
                    || (base_profile == "System" && op_row.system_forbidden)
                {
                    return Err(invalid(
                        R,
                        format!(
                            "{what}: ops_ceiling includes `{op_name}`, which is forbidden for base_profile `{base_profile}`"
                        ),
                    ));
                }
            }
            let default_ops = req_str_list(t, "default_ops", &what)?;
            for op_name in &default_ops {
                if !ops_ceiling.contains(op_name) {
                    return Err(invalid(
                        R,
                        format!(
                            "{what}: default_ops cites `{op_name}`, which is not in ops_ceiling"
                        ),
                    ));
                }
            }
            let required_caveats = req_str_list(t, "required_caveats", &what)?;
            for cav_name in &required_caveats {
                let Some(cav_row) = caveats.iter().find(|c| &c.name == cav_name) else {
                    return Err(invalid(
                        R,
                        format!("{what}: required_caveats cites unknown caveat `{cav_name}`"),
                    ));
                };
                if cav_row.status != CaveatStatus::Live {
                    return Err(invalid(
                        R,
                        format!("{what}: required_caveats cites dormant caveat `{cav_name}`"),
                    ));
                }
            }
            let summary = req_nonempty_str(t, "summary", &what)?.to_string();
            profiles.push(ProfileTemplateRow {
                name,
                base_profile,
                external,
                ops_ceiling,
                default_ops,
                required_caveats,
                summary,
            });
        }
        if profiles.is_empty() {
            return Err(invalid(R, "at least one [[profile]] row is required"));
        }

        Ok(Self {
            ops,
            caveats,
            profiles,
        })
    }

    #[must_use]
    pub fn op_by_name(&self, name: &str) -> Option<&OpRow> {
        self.ops.iter().find(|o| o.name == name)
    }

    #[must_use]
    pub fn caveat_by_name(&self, name: &str) -> Option<&CaveatRow> {
        self.caveats.iter().find(|c| c.name == name)
    }

    #[must_use]
    pub fn caveat_by_tag(&self, tag: u8) -> Option<&CaveatRow> {
        self.caveats
            .iter()
            .find(|c| c.encoding == CaveatEncoding::Tagged(tag))
    }

    #[must_use]
    pub fn profile_by_name(&self, name: &str) -> Option<&ProfileTemplateRow> {
        self.profiles.iter().find(|p| p.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_capability_caveats_load_and_cover_ops_caveats_and_profiles() {
        let reg = CapabilityCaveats::embedded().expect("capability_caveats.toml");
        assert_eq!(reg.ops.len(), 22);
        assert_eq!(reg.op_by_name("read").map(|o| o.tag), Some(0));
        assert_eq!(reg.op_by_name("partial_view").map(|o| o.tag), Some(20));
        assert_eq!(reg.op_by_name("maintain").map(|o| o.tag), Some(21));
        assert_eq!(reg.caveat_by_tag(1).map(|c| c.name.as_str()), Some("books"));
        assert_eq!(
            reg.caveat_by_tag(8).map(|c| c.name.as_str()),
            Some("possession")
        );
        assert_eq!(
            reg.caveat_by_tag(10).map(|c| c.name.as_str()),
            Some("daily_root")
        );
        assert_eq!(
            reg.caveat_by_tag(11).map(|c| c.name.as_str()),
            Some("operator_kind")
        );
        assert_eq!(
            reg.caveat_by_tag(12).map(|c| c.name.as_str()),
            Some("requires_dry_run")
        );
        assert_eq!(
            reg.caveat_by_tag(13).map(|c| c.name.as_str()),
            Some("classes")
        );
        assert_eq!(
            reg.caveat_by_name("entities").map(|c| c.status),
            Some(CaveatStatus::Dormant)
        );
        assert_eq!(reg.profiles.len(), 10);
        for expected in [
            "Agent",
            "Preparer",
            "Approver",
            "Controller",
            "Auditor",
            "Regulator",
            "Investigator",
            "Receiver",
            "Production",
            "Witness",
        ] {
            assert!(
                reg.profile_by_name(expected).is_some(),
                "missing profile `{expected}`"
            );
        }
    }

    #[test]
    fn planted_defects_in_capability_caveats_are_refused() {
        let good = CAPABILITY_CAVEATS;
        for (what, bad, expected) in [
            (
                "non-contiguous op tag",
                good.replacen("tag = 2\n", "tag = 99\n", 1),
                "contiguous",
            ),
            (
                "duplicate caveat tag",
                good.replacen(
                    "tag = 8\nname = \"possession\"\n",
                    "tag = 1\nname = \"possession\"\n",
                    1,
                ),
                "duplicate caveat tag",
            ),
            (
                "planned caveat without tracking_bead",
                good.replacen("tracking_bead = \"fa-0x0\"\n", "", 1),
                "planned",
            ),
            (
                "agent profile granting forbidden approve",
                good.replacen(
                    "ops_ceiling = [\"read\", \"post\", \"reconcile\", \"verify\", \"produce\", \"partial_view\"]",
                    "ops_ceiling = [\"read\", \"approve\"]",
                    1,
                ),
                "forbidden for base_profile `Agent`",
            ),
            (
                "default_ops outside ops_ceiling",
                good.replacen(
                    "default_ops = [\"witness\"]",
                    "default_ops = [\"close\"]",
                    1,
                ),
                "not in ops_ceiling",
            ),
            (
                "required_caveats citing dormant caveat",
                good.replacen(
                    "required_caveats = [\"ops\", \"books\"]",
                    "required_caveats = [\"ops\", \"entities\"]",
                    1,
                ),
                "dormant caveat",
            ),
        ] {
            let err = CapabilityCaveats::parse(&bad).expect_err(what);
            assert!(
                err.to_string().contains(expected),
                "{what}: expected `{expected}` in `{err}`"
            );
        }
    }
}
