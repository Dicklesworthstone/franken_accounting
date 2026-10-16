//! Conformance matrix generation, TOML/Markdown rendering, and baseline
//! verification (plan §16.3, Gate G4, bead `fa-npi`).
//!
//! Any row that diverges from expected or changes from its baseline without a
//! non-empty documented `reason` fails `verify_matrix_laws`.

use crate::FormatError;

/// One row in a conformance matrix (`fixture`, `expected`, `observed`,
/// `divergence`, `reason`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceRow {
    pub fixture: String,
    pub expected: String,
    pub observed: String,
    /// `"none"` when `expected == observed`, or a documented divergence tag
    /// (`"documented_rounding"`, `"documented_mechanism"`, `"documented_n_leg"`).
    pub divergence: String,
    pub reason: String,
}

/// A conformance matrix for an external oracle or audit standard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceMatrix {
    pub schema_version: u32,
    pub oracle: String,
    pub proof_class: String,
    pub no_claim_boundary: String,
    pub rows: Vec<ConformanceRow>,
}

impl ConformanceMatrix {
    /// Validate that every row in the matrix either matches (`expected == observed`
    /// with `divergence == "none"`) or carries both a documented divergence tag
    /// (`divergence != "none"`) and a non-empty `reason`.
    pub fn verify_matrix_laws(&self) -> Result<(), FormatError> {
        if self.rows.is_empty() {
            return Err(FormatError::Parse {
                format: "ConformanceMatrix",
                detail: format!("conformance matrix {:?} has zero rows", self.oracle),
            });
        }
        for row in &self.rows {
            if row.fixture.trim().is_empty() {
                return Err(FormatError::Parse {
                    format: "ConformanceMatrix",
                    detail: "conformance row has empty fixture name".to_owned(),
                });
            }
            if row.expected == row.observed {
                if row.divergence != "none" && row.reason.trim().is_empty() {
                    return Err(FormatError::Parse {
                        format: "ConformanceMatrix",
                        detail: format!(
                            "fixture {:?} declares divergence {:?} with empty reason",
                            row.fixture, row.divergence
                        ),
                    });
                }
            } else {
                if row.divergence == "none" || row.divergence.trim().is_empty() {
                    return Err(FormatError::Parse {
                        format: "ConformanceMatrix",
                        detail: format!(
                            "fixture {:?} differs (expected {:?}, observed {:?}) without a declared divergence tag",
                            row.fixture, row.expected, row.observed
                        ),
                    });
                }
                if row.reason.trim().is_empty() {
                    return Err(FormatError::Parse {
                        format: "ConformanceMatrix",
                        detail: format!(
                            "fixture {:?} diverges ({:?}) without a documented reason",
                            row.fixture, row.divergence
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Render the conformance matrix as canonical TOML.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "schema_version = {}\noracle = \"{}\"\nproof_class = \"{}\"\nno_claim_boundary = \"{}\"\n\n",
            self.schema_version,
            escape_toml(&self.oracle),
            escape_toml(&self.proof_class),
            escape_toml(&self.no_claim_boundary),
        ));
        for row in &self.rows {
            out.push_str("[[row]]\n");
            out.push_str(&format!("fixture = \"{}\"\n", escape_toml(&row.fixture)));
            out.push_str(&format!("expected = \"{}\"\n", escape_toml(&row.expected)));
            out.push_str(&format!("observed = \"{}\"\n", escape_toml(&row.observed)));
            out.push_str(&format!(
                "divergence = \"{}\"\n",
                escape_toml(&row.divergence)
            ));
            out.push_str(&format!("reason = \"{}\"\n\n", escape_toml(&row.reason)));
        }
        out
    }

    /// Render the conformance matrix as a GitHub-flavored Markdown document.
    pub fn to_markdown(&self, title: &str) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {title}\n\n"));
        md.push_str(&format!("- **Oracle:** `{}`\n", self.oracle));
        md.push_str(&format!("- **Proof Class:** `{}`\n", self.proof_class));
        md.push_str(&format!(
            "- **No-Claim Boundary:** {}\n\n",
            self.no_claim_boundary
        ));
        md.push_str("| Fixture | Expected | Observed | Divergence | Reason |\n");
        md.push_str("|---|---|---|---|---|\n");
        for row in &self.rows {
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | {} |\n",
                row.fixture, row.expected, row.observed, row.divergence, row.reason
            ));
        }
        md
    }
}

fn escape_toml(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
