use super::*;
use crate::findings::FindingWorkpaper;

#[test]
fn numbered_workpaper_preserves_original_text_and_paths_after_later_history() {
    let mut f = Fixture::new(118);
    let source = f.post(10, "3000", "1000", 100);
    let transfer = f.post(11, "1000", "1010", 80);
    let cert = f.certify("trace.network_fifo", Some(source));
    let run = f.record(cert.digest()).unwrap();
    let cx = f.cx();
    let first = f.runtime.block_on(f.book.finding_workpaper(&cx, PRINCIPAL, &cap(&["read", "produce"]), cert.digest())).unwrap().unwrap();
    assert_eq!(first.recorded_at(), run.recorded_at);
    assert!(first.id().ends_with(&format!("-WP-{}", run.recorded_at.0)));
    assert_eq!(first.certificate_bytes(), cert.canonical_bytes().unwrap());
    assert!(first.jsonl().contains(&format!("\"vid\":\"{:032x}\"", transfer.0)));
    assert!(first.jsonl().contains("\"value\":\"80\""));
    assert_eq!(first.jsonl().lines().filter(|l| l.contains("\"event\":\"finding\"")).count(), run.report.findings.len());
    let encoded = first.canonical_bytes().unwrap();
    assert_eq!(FindingWorkpaper::decode(&encoded).unwrap(), first);
    f = f.reopen();
    f.post(1, "3000", "1000", 1000);
    let head = f.head();
    let cx = f.cx();
    let replayed = f.runtime.block_on(f.book.replay_finding_workpaper(&cx, PRINCIPAL, &cap(&["read"]), &encoded)).unwrap().unwrap();
    assert_eq!(replayed, run);
    let again = f.runtime.block_on(f.book.finding_workpaper(&cx, PRINCIPAL, &cap(&["read", "produce"]), cert.digest())).unwrap().unwrap();
    assert_eq!(again, first);
    assert_eq!(f.head(), head, "neither replay nor export renumbers or writes");
}

#[test]
fn repaired_hash_of_false_workpaper_is_not_a_replay_and_authority_precedes_decode() {
    let mut f = Fixture::new(119);
    let source = f.post(10, "3000", "1000", 100);
    let cert = f.certify("trace.network_fifo", Some(source));
    f.record(cert.digest()).unwrap();
    let cx = f.cx();
    let paper = f.runtime.block_on(f.book.finding_workpaper(&cx, PRINCIPAL, &cap(&["read", "produce"]), cert.digest())).unwrap().unwrap();
    let mut bytes = paper.canonical_bytes().unwrap();
    // Replace display-only text with the same byte length, then repair the
    // PUBLIC checksum. The nested certificate remains untouched and valid.
    let needle = b"# Finding workpaper";
    let at = bytes.windows(needle.len()).position(|w| w == needle).unwrap();
    bytes[at + 2] = b'X';
    let end = bytes.len() - 32;
    let forged_hash = domain_digest(b"fa:finding-workpaper-digest:v1", &[&bytes[..end]]);
    bytes[end..].copy_from_slice(&forged_hash);
    assert!(FindingWorkpaper::decode(&bytes).is_ok(), "must reach replay, not framing rejection");
    let head = f.head();
    assert!(f.runtime.block_on(f.book.replay_finding_workpaper(&cx, PRINCIPAL, &cap(&["read"]), &bytes)).unwrap().is_err());
    for invalid in [&bytes[..bytes.len()-1], b"bad frame".as_slice()] {
        let result = f.runtime.block_on(f.book.replay_finding_workpaper(&cx, PRINCIPAL, &cap(&["post"]), invalid)).unwrap().unwrap_err();
        assert_eq!(result.exit, exit::SAFETY);
    }
    assert_eq!(f.runtime.block_on(f.book.finding_workpaper(&cx, PRINCIPAL, &cap(&["read"]), cert.digest())).unwrap().unwrap_err().exit, exit::SAFETY);
    assert_eq!(f.head(), head);
}

#[test]
fn an_unrecorded_or_tampered_run_has_no_exportable_workpaper() {
    let mut f = Fixture::new(120);
    f.post(10, "3000", "1000", 10);
    let cert = f.certify("jet.weekend", None);
    let cx = f.cx();
    assert!(f.runtime.block_on(f.book.finding_workpaper(&cx, PRINCIPAL, &cap(&["read", "produce"]), cert.digest())).unwrap().is_err());
    let run = f.record(cert.digest()).unwrap();
    let mut bad = WriteBatch::new(relation::CITES);
    let target = target(&run.report.findings[0].cites[0], f.book.context());
    bad.delete_edge(edge_id(relation::CITES, run.finding_ids[0], target));
    f.runtime.block_on(f.book.db.write(&cx.commit(), bad)).unwrap();
    let head = f.head();
    assert!(f.runtime.block_on(f.book.finding_workpaper(&cx, PRINCIPAL, &cap(&["read", "produce"]), cert.digest())).unwrap().is_err());
    assert_eq!(f.head(), head);
}
