//! The client verifies an approval transcript before touching its secret key.

use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_model::{Id128, principal_vid};
use fa_policy::{Profile, possession_digest};
use fgdb_types::CommitSeq;

const BOOK: Id128 = Id128([0x41; 16]);
const PROPOSAL: [u8; 32] = [0x42; 32];
const SEED: [u8; 32] = [0x43; 32];

fn token(books: Option<&[Id128]>) -> CapabilityToken {
    let secret = [0x44; 32];
    let mut capability = Capability::new(
        principal_vid("detached-controller"),
        Profile::Human,
        &[Op::Read, Op::Approve],
        principal_vid("detached-issuer"),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret));
    if let Some(books) = books {
        capability = capability.for_books(books).unwrap();
    }
    CapabilityToken::new("detached-controller", capability, secret).unwrap()
}

fn body(capability: &Capability) -> Approval {
    Approval::by(capability, Op::Approve, BOOK, PROPOSAL, 7, 0)
        .unwrap()
        .unwrap()
}

fn response(approval: &Approval) -> Response {
    let public_key = fa::SigningKey::from_seed(&SEED).public_key();
    let data = json::obj(vec![
        (
            "approval",
            json::s(hex(&approval.canonical_bytes().unwrap())),
        ),
        ("generation", Json::Int(0)),
        (
            "key_id",
            json::s(hex(&fa_policy::principal_key::key_id(&public_key))),
        ),
        ("public_key", json::s(hex(&public_key))),
    ]);
    let at = crate::cli::At {
        book: hex(&approval.book_id.0),
        branch: "00".repeat(16),
        known_at: CommitSeq(12),
        effective: "all".into(),
    };
    Response {
        op: crate::wire::Op::Run,
        exit: 0,
        stdout: format!(
            "{}\n",
            crate::cli::robot_line("approval_signing_request", data, Some(&at), &[]).render()
        ),
        stderr: String::new(),
    }
}

fn arguments(key_file: &str) -> Args {
    let mut args = Args::default();
    args.positional.push("approve".into());
    args.flags.insert("--proposal".into(), vec![hex(&PROPOSAL)]);
    args.flags
        .insert("--sign-key".into(), vec![key_file.into()]);
    args.switches.push("--json".into());
    args
}

#[test]
fn substituted_approval_fields_refuse_before_the_client_key_is_read() {
    let token = token(Some(&[BOOK]));
    let capability = token.capability();
    let original = body(capability);
    assert!(checked_request(&response(&original), capability, PROPOSAL, BOOK).is_ok());

    let mut changed = Vec::new();
    let mut other = original.clone();
    other.book_id = Id128([0x51; 16]);
    changed.push(other);
    let mut other = original.clone();
    other.approved_proposal_digest = [0x52; 32];
    changed.push(other);
    let mut other = original.clone();
    other.principal = principal_vid("another-controller");
    changed.push(other);
    let mut other = original.clone();
    other.profile = Profile::Agent;
    changed.push(other);
    let mut other = original.clone();
    other.capability_commitment = [0x53; 32];
    changed.push(other);
    let mut other = original.clone();
    other.op = Op::Post;
    changed.push(other);
    let mut other = original.clone();
    other.role = 1;
    changed.push(other);
    changed.push(original.clone().with_effects_digest([0x54; 32]));
    changed.push(original.with_target_coordinate(Id128([0x55; 16])));

    for other in changed {
        let mut sent = 0;
        let result = approve(
            &arguments("/no-client-key-may-be-read"),
            Some(&token),
            &Files::default(),
            |args| {
                sent += 1;
                assert!(args.switch("--prepare-signature"));
                assert!(args.flag("--sign-key").is_none());
                Ok(response(&other))
            },
        );
        assert!(matches!(result, Err(Fail::Internal(_))), "{other:?}");
        assert_eq!(sent, 1, "a substituted body must never be submitted");
    }
}

#[test]
fn daemon_request_requires_one_canonical_event_and_a_consistent_public_key() {
    let token = token(Some(&[BOOK]));
    let capability = token.capability();
    let good = response(&body(capability));
    let mut duplicate = good.clone();
    duplicate.stdout.push_str(&good.stdout);
    assert!(checked_request(&duplicate, capability, PROPOSAL, BOOK).is_err());

    let mut trailing_body = good.clone();
    let encoded = hex(&body(capability).canonical_bytes().unwrap());
    trailing_body.stdout = trailing_body.stdout.replace(
        &format!("\"approval\":\"{encoded}\""),
        &format!("\"approval\":\"{encoded}00\""),
    );
    assert_ne!(trailing_body.stdout, good.stdout);
    assert!(checked_request(&trailing_body, capability, PROPOSAL, BOOK).is_err());

    let mut changed_key = good.clone();
    let key_id = fa_policy::principal_key::key_id(&fa::SigningKey::from_seed(&SEED).public_key());
    changed_key.stdout = changed_key.stdout.replace(
        &format!("\"key_id\":\"{}\"", hex(&key_id)),
        &format!("\"key_id\":\"{}\"", "00".repeat(32)),
    );
    assert_ne!(changed_key.stdout, good.stdout);
    assert!(checked_request(&changed_key, capability, PROPOSAL, BOOK).is_err());

    let mut oversized = good;
    oversized.stdout = " ".repeat(4097);
    assert!(checked_request(&oversized, capability, PROPOSAL, BOOK).is_err());
}

#[test]
fn automatic_signing_requires_an_independently_bound_single_book_token() {
    let unrestricted = token(None);
    let multiple = token(Some(&[BOOK, Id128([0x61; 16])]));
    for token in [None, Some(&unrestricted), Some(&multiple)] {
        let result = approve(
            &arguments("/no-client-key-may-be-read"),
            token,
            &Files::default(),
            |_| panic!("unbound signing must refuse before any daemon request"),
        );
        assert!(matches!(result, Err(Fail::Usage(_))));
    }
}

#[test]
fn admitted_exchange_signs_locally_and_sends_neither_the_key_nor_its_path() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let directory = loop {
        let next = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(next < 1_000, "cannot create a retained client-key fixture");
        let path =
            std::env::temp_dir().join(format!("fa-detached-client-{}-{next}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create client-key fixture: {error}"),
        }
    };
    let path = directory.join("private-client.key");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).unwrap();
    writeln!(file, "{}", hex(&SEED)).unwrap();
    drop(file);

    let token = token(Some(&[BOOK]));
    let approval = body(token.capability());
    let key = fa::SigningKey::from_seed(&SEED);
    let signature = fa_policy::PrincipalSignature {
        scheme: fa_policy::principal_key::SCHEME_ED25519,
        generation: 0,
        key_id: fa_policy::principal_key::key_id(&key.public_key()),
        bytes: key.sign(&fa_policy::principal_key::approval_message(
            &approval.digest().unwrap(),
        )),
    };
    let path = path.display().to_string();
    let mut sent = 0;
    let result = approve(&arguments(&path), Some(&token), &Files::default(), |args| {
        sent += 1;
        let forwarded = format!("{args:?}");
        assert!(!forwarded.contains(&path));
        assert!(!forwarded.contains(&hex(&SEED)));
        assert!(args.flag("--sign-key").is_none());
        assert_eq!(args.flag("--proposal"), Some(hex(&PROPOSAL).as_str()));
        if sent == 1 {
            assert!(args.switch("--prepare-signature"));
            assert!(args.flag("--approval-signature").is_none());
            Ok(response(&approval))
        } else {
            assert_eq!(sent, 2);
            assert!(!args.switch("--prepare-signature"));
            assert_eq!(
                args.flag("--approval-signature"),
                Some(principal::encode_approval_signature(&signature).as_str())
            );
            Ok(Response {
                op: crate::wire::Op::Run,
                exit: 0,
                stdout: "the daemon's durable approval receipt\n".into(),
                stderr: String::new(),
            })
        }
    });
    let Ok(result) = result else {
        panic!("the admitted exchange should produce a daemon receipt");
    };
    assert_eq!(sent, 2);
    assert_eq!(result.stdout, "the daemon's durable approval receipt\n");
}

#[test]
fn refused_preparation_never_reads_a_key_or_submits_a_signature() {
    let token = token(Some(&[BOOK]));
    let mut sent = 0;
    let response = approve(
        &arguments("/no-client-key-may-be-read"),
        Some(&token),
        &Files::default(),
        |_| {
            sent += 1;
            Ok(Response {
                op: crate::wire::Op::Run,
                exit: 7,
                stdout: "the daemon's admission refusal\n".into(),
                stderr: String::new(),
            })
        },
    );
    let Ok(response) = response else {
        panic!("the daemon's original admission refusal should be returned");
    };
    assert_eq!(sent, 1);
    assert_eq!(response.exit, 7);
    assert_eq!(response.stdout, "the daemon's admission refusal\n");
}
