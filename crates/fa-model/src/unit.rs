//! The immutable unit definition persisted at genesis (plan §4.4, fa-k1u).
//! The payload is the runtime definition; scalar properties are checked
//! mirrors. A pre-payload book has no stored kind or rounding-default fact.

use fa_money::{RoundingLaw, Unit, UnitId, UnitKind, UnitRegistry};

use crate::canon::{DecodeError, EncodeError, Reader, Writer};

const MAGIC: &[u8; 4] = b"FAU\0";
pub const UNIT_SCHEMA_MAJOR: u16 = 1;
pub const UNIT_SCHEMA_MINOR: u16 = 0;
pub const MAX_UNIT_CODE_BYTES: usize = 64;

/// A complete unit version, including the numeric identity amount payloads
/// use. The default law is metadata; no operation rounds implicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitDefinition {
    pub id: UnitId,
    pub unit: Unit,
}

impl UnitDefinition {
    /// FAU\0, major/minor, id, code, unit version, scale, kind, optional
    /// currency code, default rounding law. All integers are little endian.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(UNIT_SCHEMA_MAJOR)
            .u16(UNIT_SCHEMA_MINOR)
            .u32(self.id.0)
            .str(&self.unit.code)
            .u16(self.unit.version)
            .u8(self.unit.scale);
        let (kind, iso) = match self.unit.kind {
            UnitKind::Currency { iso4217 } => (1, Some(iso4217)),
            UnitKind::Commodity => (2, None),
            UnitKind::Share => (3, None),
            UnitKind::Time => (4, None),
            UnitKind::Count => (5, None),
            UnitKind::Custom => (6, None),
        };
        w.u8(kind)
            .opt(iso.as_ref(), |w, n| {
                w.u16(*n);
            })
            .u16(self.unit.rounding_default.id());
        w.finish()
    }

    /// Unknown versions and unsupported fields are refused, as no additive
    /// default law is registered for this first payload version.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<4>("unit.magic")? != *MAGIC {
            return Err(r.invalid("unit.magic"));
        }
        if r.u16("unit.schema_major")? != UNIT_SCHEMA_MAJOR {
            return Err(r.invalid("unit.schema_major"));
        }
        if r.u16("unit.schema_minor")? != UNIT_SCHEMA_MINOR {
            return Err(r.invalid("unit.schema_minor"));
        }
        let id = UnitId(r.u32("unit.id")?);
        let code = r.str(MAX_UNIT_CODE_BYTES, "unit.code")?.to_string();
        if code.is_empty() {
            return Err(r.invalid("unit.code"));
        }
        let version = r.u16("unit.version")?;
        let scale = r.u8("unit.scale")?;
        if scale > 38 {
            return Err(r.invalid("unit.scale"));
        }
        let kind_tag = r.u8("unit.kind")?;
        let iso = r.opt("unit.iso4217", |r| r.u16("unit.iso4217"))?;
        let kind = match (kind_tag, iso) {
            (1, Some(iso4217)) => UnitKind::Currency { iso4217 },
            (2, None) => UnitKind::Commodity,
            (3, None) => UnitKind::Share,
            (4, None) => UnitKind::Time,
            (5, None) => UnitKind::Count,
            (6, None) => UnitKind::Custom,
            (1..=6, _) => return Err(r.invalid("unit.iso4217")),
            (tag, _) => return Err(r.bad_tag("unit.kind", tag)),
        };
        let law_id = r.u16("unit.rounding_default")?;
        let rounding_default = RoundingLaw::from_id(law_id)
            .ok_or_else(|| r.invalid("unit.rounding_default"))?;
        r.finish()?;
        Ok(Self {
            id,
            unit: Unit {
                code,
                version,
                scale,
                kind,
                rounding_default,
            },
        })
    }
}

/// The complete ordered table is committed at genesis, so a missing last
/// unit cannot masquerade as a book created with an older registry.
pub fn unit_table_digest(units: &UnitRegistry) -> Result<[u8; 32], EncodeError> {
    let mut w = Writer::new();
    w.u32(u32::try_from(units.len()).map_err(|_| EncodeError::LengthOverflow)?);
    for (id, unit) in units.iter() {
        let bytes = UnitDefinition {
            id,
            unit: unit.clone(),
        }
        .canonical_bytes()?;
        w.bytes(&bytes);
    }
    Ok(crate::domain_digest(b"fa:unit-table:v1", &[&w.finish()?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent bytes: USD@v0, id 0, scale 2, Currency/840, HalfEven.
    const USD: &[u8] = &[
        70, 65, 85, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 85, 83, 68, 0, 0, 2,
        1, 1, 72, 3, 3, 0,
    ];

    #[test]
    fn unit_payload_matches_independent_golden_bytes_and_every_kind_round_trips() {
        let definition = UnitDefinition {
            id: UnitId(0),
            unit: Unit {
                code: "USD".into(),
                version: 0,
                scale: 2,
                kind: UnitKind::Currency { iso4217: 840 },
                rounding_default: RoundingLaw::HalfEven,
            },
        };
        assert_eq!(definition.canonical_bytes().unwrap(), USD);
        assert_eq!(UnitDefinition::decode(USD).unwrap(), definition);

        for kind in [
            UnitKind::Currency { iso4217: 392 },
            UnitKind::Commodity,
            UnitKind::Share,
            UnitKind::Time,
            UnitKind::Count,
            UnitKind::Custom,
        ] {
            for law in RoundingLaw::ALL {
                let definition = UnitDefinition {
                    id: UnitId(37),
                    unit: Unit {
                        code: "ROUNDTRIP".into(),
                        version: 12,
                        scale: 38,
                        kind,
                        rounding_default: law,
                    },
                };
                let payload = definition.canonical_bytes().unwrap();
                assert_eq!(UnitDefinition::decode(&payload).unwrap(), definition);
            }
        }
    }

    #[test]
    fn unit_payload_refuses_truncation_versions_tags_scales_and_trailing_bytes() {
        for end in 0..USD.len() {
            assert!(UnitDefinition::decode(&USD[..end]).is_err(), "prefix {end}");
        }
        for (offset, value, what) in [
            (0, 0, "unit.magic"),
            (4, 2, "unit.schema_major"),
            (6, 1, "unit.schema_minor"),
            (12, 65, "unit.code"),
            (21, 39, "unit.scale"),
            (22, 2, "unit.iso4217"),
            (22, 255, "unit.kind"),
            (23, 2, "unit.iso4217"),
            (26, 255, "unit.rounding_default"),
        ] {
            let mut damaged = USD.to_vec();
            damaged[offset] = value;
            let error = UnitDefinition::decode(&damaged).unwrap_err();
            assert_eq!(error.what, what, "offset {offset}: {error}");
        }
        let mut trailing = USD.to_vec();
        trailing.push(0);
        assert!(UnitDefinition::decode(&trailing).is_err());
    }

    #[test]
    fn unit_schema_registry_matches_the_live_codec() {
        use fa_registry::toml::Value;
        let schema = fa_registry::toml::parse(include_str!(
            "../../../registries/object_schemas/unit.toml"
        ))
        .unwrap();
        assert_eq!(schema.root["magic_hex"].as_str(), Some("46415500"));
        assert_eq!(
            schema.root["major"].as_int(),
            Some(i128::from(UNIT_SCHEMA_MAJOR))
        );
        assert_eq!(
            schema.root["minor"].as_int(),
            Some(i128::from(UNIT_SCHEMA_MINOR))
        );
        assert_eq!(
            schema.root["max_code_bytes"].as_int(),
            Some(MAX_UNIT_CODE_BYTES as i128)
        );
        let fields: Vec<_> = schema.root["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            fields,
            [
                "magic:bytes4",
                "major:u16",
                "minor:u16",
                "id:u32",
                "code:string",
                "version:u16",
                "scale:u8",
                "kind:u8",
                "iso4217:option<u16>",
                "rounding_default:u16",
            ]
        );
    }
}
