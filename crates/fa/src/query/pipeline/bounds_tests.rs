use super::tests::Fixture;
use super::*;

#[test]
fn pipeline_refuses_unrepresentable_amounts_and_parameter_overflow() {
    let mut f = Fixture::new();
    let invoice = f.post(f.proposal("invoice", "2026-03-01", f.usd, "ar", "sales", 1));
    let fa_query::Selection::Native(native) = fa_query::rewrite("MATCH (l:Leg) CALL fa.open_amount(l) YIELD open, age_days RETURN open EFFECTIVE AT '2026-03-31'").unwrap().selection else { panic!("native"); };
    let procedure = native.open_amount().unwrap();
    let mut items = f
        .book
        .open_items_as_of(None, DateDay::parse("2026-03-31").unwrap(), None)
        .unwrap()
        .items;
    let leg = fa_journal::rows::leg_vid(invoice.vid, 0);
    let item = items
        .iter_mut()
        .find(|item| item.entry == invoice.vid && item.ordinal == 0)
        .unwrap();
    item.open = i128::MAX;
    let rows = || vec![vec![GraphAggregateValue::Value(GraphValue::Vertex(leg))]];
    let refusal = parameters(f.book.context(), procedure, rows(), &items).unwrap_err();
    assert_eq!(refusal.code, code::QUERY_AMOUNT_LAW);

    let fa_query::Selection::Native(native) = fa_query::rewrite("MATCH (l:Leg) CALL fa.open_amount(l) YIELD open, age_days RETURN l.amount_bytes EFFECTIVE AT '2026-03-31'").unwrap().selection else { panic!("native"); };
    let row = vec![
        GraphAggregateValue::Value(GraphValue::Vertex(leg)),
        GraphAggregateValue::Value(GraphValue::Scalar(
            CanonicalScalar::bytes(vec![0x95; MAX_PARAMETER_BYTES]).unwrap(),
        )),
    ];
    let refusal = parameters(
        f.book.context(),
        native.open_amount().unwrap(),
        vec![row],
        &[],
    )
    .unwrap_err();
    assert_eq!(refusal.code, code::QUERY_PROFILE);
    assert!(refusal.message.contains("64 KiB"));
}
