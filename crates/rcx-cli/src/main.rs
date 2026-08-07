#![forbid(unsafe_code)]

//! `rcx` — command-line verification for the RCX protocol (`rcx-spec/v1`).
//!
//! Verifies bytes you already hold. It performs no network I/O by design: a
//! verification tool that fetches could be fooled into fetching from the party it
//! is supposed to be checking.
//!
//! Exit codes, chosen so scripts can tell the three outcomes apart:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | verified |
//! | 1 | **did not** verify — a real negative result |
//! | 2 | could not run the check (bad usage, unreadable file, malformed input) |
//!
//! Collapsing 1 and 2 is the mistake that makes CI green when a path was
//! mistyped. "We could not look" is not "we looked and it was fine".

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use rcx_verify::{
    verify_history, verify_namespace, verify_publisher, verify_receipt, verify_snapshot, ChainKind,
    Entry,
};
use serde_json::Value;

const USAGE: &str = "\
rcx — offline verification for the RCX protocol (rcx-spec/v1)

USAGE:
    rcx verify receipt      <file> --key <hex|@file>
    rcx verify snapshot     <file> --root <hex>
    rcx verify declaration  <file> --hash <hex>
    rcx verify namespace    <file> --hash <hex> --name <namespace>
    rcx verify chain        <file> --key <hex|@file> --kind <snapshot|entry-enriched>

    rcx --version
    rcx --help

INPUT FORMATS:
    receipt / chain   canonical CBOR, as raw bytes or as hex text (auto-detected).
                      A chain file is a JSON array of hex strings, oldest first.
    snapshot          JSON array of {\"name\",\"version\",\"canonical_json\"}.
    declaration       the raw JSON document, byte for byte as published.

OPTIONS:
    --key <hex|@file>   32-byte ed25519 public key. @file reads it from a file.
    --root <hex>        expected 32-byte snapshot root.
    --hash <hex>        expected 32-byte declaration hash.
    --name <namespace>  the namespace a declaration is claimed to own.
    --kind <k>          chain link rule. Required, never inferred: snapshot chains
                        link root-to-root, enrichment chains receipt-to-receipt.
    --json              emit a machine-readable result instead of prose.

EXIT CODES:
    0  verified
    1  did not verify
    2  could not run the check (usage, I/O, malformed input)

This tool performs no network I/O.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match run(&args) {
        Ok(outcome) => outcome.report(),
        Err(failure) => {
            eprintln!("rcx: {failure}");
            ExitCode::from(2)
        }
    }
}

enum Outcome {
    /// The check ran and the subject verified.
    Verified {
        what: String,
        detail: String,
        json: bool,
    },
    /// The check ran and the subject did not verify. Not an error — a result.
    Rejected {
        what: String,
        code: String,
        detail: String,
        json: bool,
    },
    /// Nothing was verified; the user asked for information.
    Message(String),
}

impl Outcome {
    fn report(self) -> ExitCode {
        match self {
            Self::Message(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Self::Verified { what, detail, json } => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"valid": true, "subject": what, "detail": detail})
                    );
                } else {
                    println!("ok  {what} verified");
                    if !detail.is_empty() {
                        println!("    {detail}");
                    }
                }
                ExitCode::SUCCESS
            }
            Self::Rejected {
                what,
                code,
                detail,
                json,
            } => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"valid": false, "subject": what, "error": code, "detail": detail})
                    );
                } else {
                    println!("FAIL {what} did NOT verify");
                    println!(
                        "    {code}{}",
                        if detail.is_empty() {
                            String::new()
                        } else {
                            format!(": {detail}")
                        }
                    );
                }
                ExitCode::from(1)
            }
        }
    }
}

fn run(args: &[String]) -> Result<Outcome, String> {
    if args.is_empty() {
        return Ok(Outcome::Message(USAGE.to_string()));
    }
    match args[0].as_str() {
        "--help" | "-h" | "help" => return Ok(Outcome::Message(USAGE.to_string())),
        "--version" | "-V" => {
            return Ok(Outcome::Message(format!(
                "rcx {} (rcx-spec/v1, rcx-verify-contract/1)\n",
                env!("CARGO_PKG_VERSION")
            )))
        }
        "verify" => {}
        other => return Err(format!("unknown command `{other}`. Try `rcx --help`.")),
    }

    let subject = args.get(1).ok_or_else(|| {
        "verify what? one of: receipt, snapshot, declaration, namespace, chain".to_string()
    })?;
    let path = args
        .get(2)
        .ok_or_else(|| format!("`rcx verify {subject}` needs a file path"))?;
    let flags = Flags::parse(&args[3..])?;

    match subject.as_str() {
        "receipt" => verify_receipt_command(path, &flags),
        "snapshot" => verify_snapshot_command(path, &flags),
        "declaration" => verify_declaration_command(path, &flags),
        "namespace" => verify_namespace_command(path, &flags),
        "chain" => verify_chain_command(path, &flags),
        other => Err(format!(
            "cannot verify `{other}`. Expected: receipt, snapshot, declaration, namespace, chain"
        )),
    }
}

#[derive(Default)]
struct Flags {
    key: Option<String>,
    root: Option<String>,
    hash: Option<String>,
    name: Option<String>,
    kind: Option<String>,
    json: bool,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut flags = Self::default();
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            // Skip empty arguments. GitHub Actions passes an unset Docker-action
            // arg as an empty string rather than omitting it, so without this the
            // action would have to build argv in a shell — and the runtime image
            // deliberately has no shell.
            if flag.is_empty() {
                index += 1;
                continue;
            }
            if flag == "--json" {
                flags.json = true;
                index += 1;
                continue;
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("`{flag}` needs a value"))?
                .clone();
            match flag {
                "--key" => flags.key = Some(value),
                "--root" => flags.root = Some(value),
                "--hash" => flags.hash = Some(value),
                "--name" => flags.name = Some(value),
                "--kind" => flags.kind = Some(value),
                other => return Err(format!("unknown option `{other}`. Try `rcx --help`.")),
            }
            index += 2;
        }
        Ok(flags)
    }

    fn require(&self, which: &str) -> Result<&String, String> {
        let value = match which {
            "--key" => self.key.as_ref(),
            "--root" => self.root.as_ref(),
            "--hash" => self.hash.as_ref(),
            "--name" => self.name.as_ref(),
            "--kind" => self.kind.as_ref(),
            _ => None,
        };
        value.ok_or_else(|| format!("`{which}` is required for this check"))
    }
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

fn verify_receipt_command(path: &str, flags: &Flags) -> Result<Outcome, String> {
    let bytes = read_cbor(path)?;
    let key = read_key(flags.require("--key")?)?;

    match verify_receipt(&bytes, &key) {
        Ok(facts) => {
            let mut detail = String::new();
            let _ = write!(detail, "receipt_hash {}", hex::encode(facts.receipt_hash));
            if !facts.signer_kid.is_empty() {
                let _ = write!(detail, ", signer_kid {}", facts.signer_kid);
            }
            Ok(Outcome::Verified {
                what: describe(path, "receipt"),
                detail,
                json: flags.json,
            })
        }
        Err(error) => Ok(rejected(path, "receipt", &error, flags.json)),
    }
}

fn verify_snapshot_command(path: &str, flags: &Flags) -> Result<Outcome, String> {
    let root = read_digest(flags.require("--root")?, "--root")?;
    let raw = fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let parsed: Value =
        serde_json::from_str(&raw).map_err(|error| format!("{path} is not JSON: {error}"))?;
    let items = parsed
        .as_array()
        .ok_or_else(|| format!("{path} must be a JSON array of snapshot entries"))?;

    let mut entries = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let field = |name: &str| -> Result<String, String> {
            item.get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("entry {index} in {path} is missing string `{name}`"))
        };
        entries.push(Entry::new(
            field("name")?,
            field("version")?,
            field("canonical_json")?,
        ));
    }

    match verify_snapshot(&entries, &root) {
        Ok(()) => Ok(Outcome::Verified {
            what: describe(path, "snapshot"),
            detail: format!("{} entries digest to the published root", entries.len()),
            json: flags.json,
        }),
        Err(error) => Ok(rejected(path, "snapshot", &error, flags.json)),
    }
}

fn verify_declaration_command(path: &str, flags: &Flags) -> Result<Outcome, String> {
    let expected = read_digest(flags.require("--hash")?, "--hash")?;
    // Read as text, byte for byte. Canonical JSON is derived from the published
    // bytes, so re-serialising through a parser first would be a different input.
    let text = fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;

    match verify_publisher(&text, &expected) {
        Ok(()) => Ok(Outcome::Verified {
            what: describe(path, "declaration"),
            detail: format!("hashes to {}", hex::encode(expected)),
            json: flags.json,
        }),
        Err(error) => Ok(rejected(path, "declaration", &error, flags.json)),
    }
}

fn verify_namespace_command(path: &str, flags: &Flags) -> Result<Outcome, String> {
    let expected = read_digest(flags.require("--hash")?, "--hash")?;
    let name = flags.require("--name")?;
    let text = fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;

    match verify_namespace(&text, &expected, name) {
        Ok(()) => Ok(Outcome::Verified {
            what: format!("namespace {name}"),
            // Say plainly what this does and does not establish, so nobody reads
            // a green line as proof of ownership. CONTRACT.md §4. The missing
            // piece is publisher-rights records, NOT the signing key — that is
            // published (spec v1 §5.6.1), so do not name it here.
            detail: "declaration hashes as published and claims this namespace. \
                     NOTE: this is internal consistency, not operator-independent \
                     proof of ownership — production publishes no publisher-rights \
                     records to bind this namespace to its publisher."
                .to_string(),
            json: flags.json,
        }),
        Err(error) => Ok(rejected(path, "namespace", &error, flags.json)),
    }
}

fn verify_chain_command(path: &str, flags: &Flags) -> Result<Outcome, String> {
    let key = read_key(flags.require("--key")?)?;
    let kind = match flags.require("--kind")?.as_str() {
        "snapshot" => ChainKind::Snapshot,
        "entry-enriched" | "entryEnriched" => ChainKind::EntryEnriched,
        other => {
            return Err(format!(
                "unknown chain kind `{other}`. Expected `snapshot` or `entry-enriched`. \
                 The kind is never inferred: snapshot chains link root-to-root while \
                 enrichment chains link receipt-to-receipt, so the wrong rule fails a \
                 sound chain in a way that looks like tampering."
            ))
        }
    };

    let raw = fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let parsed: Value =
        serde_json::from_str(&raw).map_err(|error| format!("{path} is not JSON: {error}"))?;
    let items = parsed
        .as_array()
        .ok_or_else(|| format!("{path} must be a JSON array of hex-encoded receipts"))?;

    let mut links = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let text = item
            .as_str()
            .ok_or_else(|| format!("link {index} in {path} is not a hex string"))?;
        links.push(
            hex::decode(text.trim())
                .map_err(|error| format!("link {index} in {path} is not hex: {error}"))?,
        );
    }
    if links.is_empty() {
        return Err(format!("{path} contains no links"));
    }

    match verify_history(&links, &key, kind) {
        Ok(()) => Ok(Outcome::Verified {
            what: describe(path, "chain"),
            detail: format!("{} links verify and chain unbroken", links.len()),
            json: flags.json,
        }),
        Err(error) => Ok(rejected(path, "chain", &error, flags.json)),
    }
}

// ---------------------------------------------------------------------------
// input helpers
// ---------------------------------------------------------------------------

fn describe(path: &str, what: &str) -> String {
    format!("{what} {}", Path::new(path).display())
}

fn rejected(path: &str, what: &str, error: &rcx_verify::VerifyError, json: bool) -> Outcome {
    let code = error.code().to_string();
    let rendered = error.to_string();
    // Most errors Display as exactly their code, so printing both gives
    // "root_mismatch: root_mismatch". Only carry the detail when it adds something.
    let detail = if rendered == code {
        String::new()
    } else {
        rendered
    };
    Outcome::Rejected {
        what: describe(path, what),
        code,
        detail,
        json,
    }
}

/// Read canonical CBOR from a file that may hold raw bytes or hex text.
///
/// Auto-detecting is a convenience, but a wrong guess would be indistinguishable
/// from tampering, so hex is only accepted when the entire trimmed contents are
/// valid hex of even length — anything else is treated as raw bytes.
fn read_cbor(path: &str) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    if bytes.is_empty() {
        return Err(format!("{path} is empty"));
    }

    if let Ok(text) = std::str::from_utf8(&bytes) {
        let trimmed = text.trim();
        if !trimmed.is_empty()
            && trimmed.len() % 2 == 0
            && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return hex::decode(trimmed)
                .map_err(|error| format!("{path} looked like hex but did not decode: {error}"));
        }
    }
    Ok(bytes)
}

/// Read a 32-byte key from a hex string, or from a file when prefixed with `@`.
fn read_key(value: &str) -> Result<Vec<u8>, String> {
    let text = match value.strip_prefix('@') {
        Some(path) => fs::read_to_string(path)
            .map_err(|error| format!("cannot read key file {path}: {error}"))?,
        None => value.to_string(),
    };
    let bytes =
        hex::decode(text.trim()).map_err(|error| format!("key is not valid hex: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!("key must be 32 bytes, got {}", bytes.len()));
    }
    Ok(bytes)
}

fn read_digest(value: &str, flag: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(value.trim()).map_err(|error| format!("{flag} is not valid hex: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!("{flag} must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
