//! The catalog the surfaces call (plan §11.1; Appendix D `fa procedure
//! list|run <id>`): every registered row, and a registered procedure built
//! from its id, explicit parameters and declared inputs passed by handle.
//! A row that exists in `procedures.toml` but has no implementation in this
//! build is refused by name, never silently skipped.

mod network;
pub use network::NetworkTrace;

use fa_registry::procedures::{Procedure as Row, Procedures};
use fgdb_types::VId;

use crate::aging::OpenItemsAging;
use crate::cutoff::PeriodBoundary;
use crate::digits::FirstDigit;
use crate::duplicates::{SameSameDifferent, SameSameSame};
use crate::graph::{RoundTrips, Structuring};
use crate::jet::{
    PeriodEndTiming, PostClosing, RoundAmounts, SelfApproved, ThinDescriptions, Weekend,
};
use crate::numbers::SequenceGaps;
use crate::trace::{Law, Trace};
use crate::{LanternError, Params, Procedure};

/// Declared inputs a surface passes by handle; a procedure that declares
/// one and does not receive it is refused naming the input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inputs {
    pub account: Option<VId>,
    pub source: Option<VId>,
}

/// Every registered row, in registry order.
pub fn registered() -> Result<Vec<Row>, LanternError> {
    Ok(Procedures::embedded()?.rows)
}

/// Build the registered procedure `id` with `params` (which must belong to
/// `id`) and `inputs`.
pub fn build(id: &str, params: Params, inputs: Inputs) -> Result<Box<dyn Procedure>, LanternError> {
    let row = crate::bind(id)?;
    let need = |name: &str, handle: Option<VId>| {
        handle.ok_or_else(|| LanternError::Parameter {
            procedure: row.id.clone(),
            name: name.to_string(),
            message: format!("declared input `{name}` is required; pass it by handle"),
        })
    };
    let procedure: Box<dyn Procedure> = match id {
        RoundAmounts::ID => Box::new(RoundAmounts::with(params)),
        PeriodEndTiming::ID => Box::new(PeriodEndTiming::with(params)),
        PostClosing::ID => Box::new(PostClosing::with(params)),
        Weekend::ID => Box::new(Weekend::with(params)),
        SelfApproved::ID => Box::new(SelfApproved::with(params)),
        ThinDescriptions::ID => Box::new(ThinDescriptions::with(params)),
        SameSameSame::ID => Box::new(SameSameSame::with(params)),
        SameSameDifferent::ID => Box::new(SameSameDifferent::with(params)),
        SequenceGaps::ID => Box::new(SequenceGaps::with(params)),
        PeriodBoundary::ID => Box::new(PeriodBoundary::with(params)),
        FirstDigit::ID => Box::new(FirstDigit::with(params)),
        OpenItemsAging::ID => Box::new(OpenItemsAging::with(params)),
        RoundTrips::ID => Box::new(RoundTrips::with(params)),
        Structuring::ID => Box::new(Structuring::with(params)),
        "trace.network_fifo" | "trace.network_lifo" | "trace.network_libr" | "trace.network_pro_rata" => Box::new(NetworkTrace::with(
            id, params, need("account", inputs.account)?, need("source", inputs.source)?,
        )?),
        "trace.libr" | "trace.fifo" | "trace.lifo" | "trace.pro_rata" => {
            let law = match id {
                "trace.libr" => Law::Libr,
                "trace.fifo" => Law::Fifo,
                "trace.lifo" => Law::Lifo,
                _ => Law::ProRata,
            };
            let account = need("account", inputs.account)?;
            let source = need("source", inputs.source)?;
            Box::new(Trace::with(law, params, account, source))
        }
        _ => {
            return Err(LanternError::Parameter {
                procedure: row.id.clone(),
                name: "id".into(),
                message: "registered in procedures.toml but not implemented in this build".into(),
            });
        }
    };
    Ok(procedure)
}

#[cfg(test)]
mod network_tests {
    use super::*;

    #[test]
    fn network_catalog_requires_both_handles_and_matches_the_registry() {
        for id in ["trace.network_fifo", "trace.network_lifo", "trace.network_libr", "trace.network_pro_rata"] {
            let p = build(id, Params::defaults(id).unwrap(), Inputs { account: Some(VId(1)), source: Some(VId(2)) }).unwrap();
            assert_eq!(p.id(), id);
            assert_eq!(p.version(), crate::bind(id).unwrap().version);
            assert_eq!(p.inputs().len(), 2);
            for input in [Inputs::default(), Inputs { account: Some(VId(1)), source: None }] {
                assert!(matches!(build(id, Params::defaults(id).unwrap(), input), Err(LanternError::Parameter { .. })));
            }
        }
    }
}
