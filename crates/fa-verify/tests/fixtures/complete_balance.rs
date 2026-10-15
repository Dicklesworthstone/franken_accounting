//! Independent v3 process-test fixture. This is a new synthetic journal,
//! not a regenerated accumulator_v1 golden or an assertion of kernel admission.

use fa_verify::blake3::hash_parts;
use fa_verify::codec::Writer;
use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use fa_verify::Checkpoint;

pub fn fixture() -> (Vec<u8>, Checkpoint) {
    let mut entry = Writer::default();
    entry.u16(1).u16(0).fixed(&[0x5a; 16]).fixed(&[0; 16])
        .u16(1).i32(20_527).u8(0);
    // Canonical erasable description; no plaintext content is needed here.
    entry.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
    entry.u8(0).count(2);
    for (side, account) in [(0, 0x20), (1, 0x30)] {
        entry.u8(side).u128(account).u32(1).i128(120_550)
            .u8(0).count(0).u8(0).count(0);
    }
    entry.u8(0).count(1).u32(1).i128(120_550).i128(120_550)
        .u8(0).bytes(b"complete-cli")
        .u8(0).fixed(&[0; 32]).u16(1)
        .u128(1).u8(0).count(0).count(0).u8(0).count(0).count(0);
    let proposal_len = entry.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&entry.buf]);
    let admission = [0; 5]; // no plan certificate, no approvals
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &admission]);
    entry.fixed(&admission).fixed(&proposal).fixed(&digest);
    let envelope = envelope_of_entry(&entry.buf, proposal_len, 1, 0).unwrap().encode();
    // This fixture owns a separate, explicitly trusted checkpoint. It never
    // borrows the old golden's anchor for a different record set.
    let checkpoint = Checkpoint {
        book_id: [0x5a; 16], branch_id: [0; 16], through_seq: 1,
        leaf_count: 1, root: fa_verify::tree::leaf_hash(&envelope),
    };
    let mut proof = Writer::default();
    proof.bytes(fa_verify::migration_balance::BALANCE_FORMAT_V3)
        .fixed(&checkpoint.encode()).u128(0x30).u32(1).u8(0)
        .i128(0).i128(120_550)
        .count(1).bytes(&envelope)
        .count(1).u64(0).u32(u32::try_from(proposal_len).unwrap()).bytes(&entry.buf)
        .count(0);
    (proof.buf, checkpoint)
}
