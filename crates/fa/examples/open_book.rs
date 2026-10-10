//! Create an in-memory book, install a three-account chart, open March 2026,
//! post rent, read it back, then watch the kernel refuse an unbalanced entry.
//!
//! Exit codes follow the contract (plan §15.3): 0 on success, 5 when the
//! foundation fails. The refusal at the end is the expected, lawful outcome.

use std::process::ExitCode;

use fa::book::{Book, BookError, BookKeys, Entropy};
use fa_journal::{AccountSpec, BookSpec, Capability, PostRequest, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid};
use fa_money::{Amount, Side};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb_types::VId;

fn run() -> Result<(), BookError> {
    let calendar =
        FiscalCalendar::monthly("cal", 1, 1).map_err(|e| BookError::Runtime(format!("{e:?}")))?;
    let units = fa_registry::units_embedded()?;
    let usd = units
        .lookup("USD")
        .ok_or_else(|| BookError::Runtime("USD missing".into()))?;
    let book_id = Id128([0x42; 16]);
    let spec = BookSpec {
        book_id,
        name: "Example Co".into(),
        base_unit: usd,
        calendar,
    };
    let mut book =
        Book::create_memory(BookKeys::for_development(0x5a), spec, Entropy::production())?;
    let principal = VId(1);
    let day = DateDay::from_ymd(2026, 3, 15).map_err(|e| BookError::Runtime(format!("{e:?}")))?;

    let chart = vec![
        AccountSpec {
            code: "1".into(),
            name: "Assets".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: false,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
        },
        AccountSpec {
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: Some("1".into()),
        },
        AccountSpec {
            code: "6000".into(),
            name: "Rent expense".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
        },
    ];
    match book.install_chart(&chart, principal, day, b"chart-v1")? {
        Ok(c) => println!(
            "chart installed: {} accounts, control entry {:?}, recorded_at {:?}",
            c.accounts, c.control_entry, c.recorded_at
        ),
        Err(r) => println!("chart refused: {r}"),
    }
    let (_, periods) = book.create_periods(2026)?;
    let march = periods
        .iter()
        .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
        .map(|p| p.code.clone())
        .ok_or_else(|| BookError::Runtime("no March period".into()))?;
    match book.transition_period(
        &march,
        PeriodTransition::Open,
        principal,
        1,
        day,
        b"open-march",
    )? {
        Ok(t) => println!(
            "period {}: {} → {} at {:?}",
            t.period,
            t.from.name(),
            t.to.name(),
            t.recorded_at
        ),
        Err(r) => println!("transition refused: {r}"),
    }

    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, "6000"),
            Amount::new(usd, 150_000),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, "1000"),
            Amount::new(usd, 150_000),
        ),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day,
        document_date: None,
        description: book.seal_text("March rent")?,
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs)
            .map_err(fa_journal::KernelError::Model)?,
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"rent-2026-03".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
    };
    let mut unbalanced = proposal.clone();
    unbalanced.idempotency_key = b"rent-typo".to_vec();
    unbalanced.legs[1].amount.mantissa -= 1;
    unbalanced.unit_totals =
        EntryPayload::fold_unit_totals(&unbalanced.legs).map_err(fa_journal::KernelError::Model)?;
    let request = |p: EntryPayload| PostRequest {
        proposal: p,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::with_ops(&["post"]),
    };

    match book.post(request(proposal))? {
        Ok(posted) => {
            let r = posted.entry_ref();
            let hex: String = r.entry_digest.iter().map(|b| format!("{b:02x}")).collect();
            println!(
                "posted: vid {:?}, entry_digest {hex}, recorded_at {:?}, period {:?}",
                r.vid,
                posted.recorded_at(),
                posted.period()
            );
            if let Some((entry, _)) = book.read_entry(r.vid)? {
                println!(
                    "read back: {} legs, class {:?}, digests verified",
                    entry.proposal.legs.len(),
                    entry.proposal.class.name()
                );
            }
        }
        Err(r) => println!("post refused: {r}"),
    }
    match book.post(request(unbalanced))? {
        Ok(_) => println!("UNEXPECTED: the unbalanced entry was admitted"),
        Err(r) => println!("refused as expected: {r}"),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("foundation failure: {e}");
            ExitCode::from(5)
        }
    }
}
