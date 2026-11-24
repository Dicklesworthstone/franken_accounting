//! Client-held approval signing across the existing daemon command protocol.
//! Only public approval data and the resulting signature cross the socket.
//! The exact requested digest and authority are checked before the key is read.
//! The explicit key path resolves in the client's own Files context; the
//! daemon's file grants govern only files the daemon itself may read.

use fa_policy::{Approval, Capability, CapabilityToken, Op};

use crate::args::Args;
use crate::cli::{Fail, Files, hex, usage};
use crate::json::{self, Json};
use crate::principal::{self, APPROVAL_SIGNING_EXAMPLE};
use crate::wire::Response;

fn invalid(message: impl Into<String>) -> Fail {
    Fail::Internal(format!(
        "invalid daemon approval signing request: {}",
        message.into()
    ))
}

fn string<'a>(value: &'a Json, name: &str) -> Result<&'a str, Fail> {
    value
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| invalid(format!("missing {name}")))
}

fn approval_body(text: &str) -> Result<Vec<u8>, Fail> {
    // Current Approval bodies fit 160 bytes. A detached request is never a
    // stored signed record or an unbounded daemon-selected message.
    if text.len() > 320
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("approval body is not bounded hexadecimal"));
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid("approval hex"))?;
            u8::from_str_radix(pair, 16).map_err(|_| invalid("approval hex"))
        })
        .collect()
}

/// Validate a public preparation without relying on its claimed human-readable
/// labels. A daemon cannot choose another digest, holder, scope, role or op for
/// the local key to sign. Its epoch/key generation are checked again by the
/// kernel when the detached signature is submitted.
fn checked_request(
    response: &Response,
    capability: &Capability,
    proposal_digest: [u8; 32],
    expected_book: fa_model::Id128,
) -> Result<fa::book::ApprovalSigningRequest, Fail> {
    if response.stdout.len() > 4096 {
        return Err(invalid("response exceeds the approval request bound"));
    }
    let mut lines = response.stdout.lines();
    let line = lines.next().ok_or_else(|| invalid("missing response"))?;
    if lines.next().is_some() {
        return Err(invalid("expected exactly one approval request"));
    }
    let registry = crate::verbs::registry().map_err(invalid)?;
    if registry.check_line(line).map_err(invalid)? != "approval_signing_request" {
        return Err(invalid("unexpected event"));
    }
    let envelope = json::parse(line).map_err(|error| invalid(error.to_string()))?;
    let data = envelope
        .get("data")
        .ok_or_else(|| invalid("missing data"))?;
    let body = approval_body(string(data, "approval")?)?;
    let approval = Approval::decode(&body).map_err(|error| invalid(error.to_string()))?;
    if approval
        .canonical_bytes()
        .map_err(|error| invalid(error.to_string()))?
        != body
    {
        return Err(invalid("approval must be its canonical unsigned body"));
    }
    let expected_commitment = capability
        .commitment()
        .map_err(|error| invalid(error.to_string()))?;
    if approval.book_id != expected_book
        || approval.approved_proposal_digest != proposal_digest
        || approval.principal != capability.holder()
        || approval.profile != capability.sod_profile()
        || approval.capability_commitment != expected_commitment
        || approval.op != Op::Approve
        || approval.role != 0
        || approval.effects_digest.is_some()
        || approval.target_coordinate.is_some()
        || string(&envelope, "book")? != hex(&approval.book_id.0)
        || capability
            .books()
            .is_some_and(|books| !books.contains(&approval.book_id))
    {
        return Err(invalid(
            "approval differs from the client's digest, authority or book scope",
        ));
    }
    let generation = match data.get("generation") {
        Some(Json::Int(value)) => {
            u32::try_from(*value).map_err(|_| invalid("invalid key generation"))?
        }
        _ => return Err(invalid("missing key generation")),
    };
    let key_id = crate::proof::fixed_hex(string(data, "key_id")?, "approval key id")?;
    let public_key = crate::proof::fixed_hex(string(data, "public_key")?, "approval public key")?;
    if fa_policy::principal_key::key_id(&public_key) != key_id {
        return Err(invalid("public key and key id disagree"));
    }
    Ok(fa::book::ApprovalSigningRequest {
        approval,
        generation,
        key_id,
        public_key,
    })
}

pub(super) fn approve(
    parsed: &Args,
    token: Option<&CapabilityToken>,
    files: &Files,
    mut send: impl FnMut(&Args) -> Result<Response, Fail>,
) -> Result<Response, Fail> {
    let digest = principal::single_approval_digest(parsed)?;
    if parsed.flag_all("--sign-key").len() != 1
        || parsed.flag("--approval-signature").is_some()
        || parsed.switch("--prepare-signature")
    {
        return Err(usage(
            "use exactly one --sign-key for the automatic client signing exchange",
            APPROVAL_SIGNING_EXAMPLE,
        ));
    }
    // The daemon supplies an approval body, not the identity of the book the
    // client intended to approve. Bind that identity independently to the
    // holder's issued, single-book token before asking for or signing a body.
    let capability = token
        .ok_or_else(|| {
            usage(
                "client signing through fad requires an issued token confined to this book",
                "issue a Human approval token with --book-scope, then pass --token <file>",
            )
        })?
        .capability();
    let expected_book = capability
        .books()
        .filter(|books| books.len() == 1)
        .and_then(|books| books.first())
        .copied()
        .ok_or_else(|| {
            usage(
                "client signing through fad requires exactly one book in the token's scope",
                "issue the approval token with --book-scope for the intended book",
            )
        })?;
    let mut commit = parsed.clone();
    commit.flags.remove("--sign-key");
    let mut prepare = commit.clone();
    prepare.flags.remove("--format");
    prepare.switches.retain(|switch| switch != "--json");
    prepare.switches.push("--json".into());
    prepare.switches.push("--prepare-signature".into());
    let response = send(&prepare)?;
    if response.exit != 0 {
        // An admission refusal never reads a key or submits an approval.
        return Ok(response);
    }
    let request = checked_request(&response, capability, digest, expected_book)?;
    let key = principal::load_principal_key_from_files(files, false, parsed, "--sign-key")?
        .ok_or_else(|| usage("missing client signing key", APPROVAL_SIGNING_EXAMPLE))?;
    if key.public_key() != request.public_key {
        return Err(Fail::Refusal(fa_journal::Refusal::new(
            "FA-REF-205",
            fa_journal::exit::SAFETY,
            "the client key is not the principal's current registered signing key",
            "plan §14.5; fa-z46b",
            "use --sign-key <the principal's current registered key file>",
        )));
    }
    let digest = request
        .approval
        .digest()
        .map_err(|error| invalid(error.to_string()))?;
    let signature = fa_policy::PrincipalSignature {
        scheme: fa_policy::principal_key::SCHEME_ED25519,
        generation: request.generation,
        key_id: request.key_id,
        bytes: key.sign(&fa_policy::principal_key::approval_message(&digest)),
    };
    commit.flags.insert(
        "--approval-signature".into(),
        vec![principal::encode_approval_signature(&signature)],
    );
    send(&commit)
}

#[cfg(test)]
mod tests;
