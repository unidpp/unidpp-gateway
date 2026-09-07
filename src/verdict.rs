//! The verdict rules of the py adapter, ported —
//! `unidpp-py/unidpp/verify.py` (I13 degradation ladder + I9 verdicts).
//!
//! Ports of: the freshness assessment, the trust-marker ladder, the
//! outcome combination (`fail` > `degraded` > `pass`), the pluggable
//! crypto-slot registry with its degrade-never-fake doctrine, the
//! coverage report, and the finding taxonomy (severity/code/message
//! with the py codes: `validity-window`, `recall-stale`,
//! `suite-unsupported`, `key-unanchored`, `signature-voided`,
//! `signature-invalid`, `below-minimum-marker`).
//!
//! Deviations from the py original, all documented:
//!
//! - **Evidence is the CLI passport document, not a Tier-A pack.** The
//!   py pipeline (`verify_tier_a_pack`) validates a carrier pack; the
//!   gateway renders full passports, so the same rule ladder runs over
//!   `unidpp/passport@1` documents: the schema leg is satisfied by the
//!   document already having parsed into the typed core (a raw-JSON
//!   schema failure cannot reach this code), the validity window and
//!   freshness legs are identical, and the signature legs run over the
//!   document's recorded event signatures (the signed payload is the
//!   event's canonical body — the role `signed_payload` plays for
//!   packs).
//! - **The HMAC test slot is not ported** (no symmetric keys exist in
//!   this service); instead a real Ed25519 slot is registered — the
//!   suite the `unidpp-issuer` signs events with — using
//!   `unidpp-signatif` cryptography. This is the py
//!   slot-pluggability model exercised with the production suite: a
//!   real verifier, not a mock.
//! - **Marker vocabulary.** The py ladder says `third-party-attested`;
//!   the Rust core's `TrustMarker` token for the same grade is
//!   `attested`. Verdicts here use the py vocabulary (they are the
//!   adapter's semantics); the EN/UNTP renders report core tokens.
//! - **Taint** is accepted as an option (fail under every reading,
//!   exactly as py) but the gateway itself never marks taint.

use std::collections::HashMap;

use serde_json::{json, Value};
use unidpp_cli::passport::Passport;
use unidpp_model::Timestamp;

// ---------------------------------------------------------------------------
// Marker ladder + outcome combination (model.py verdicts, via verify.py)
// ---------------------------------------------------------------------------

/// Graded trust markers, weakest to strongest (the py
/// `TRUST_MARKERS`/`MARKER_ORDER`).
pub const MARKER_ORDER: [&str; 5] = [
    "unsigned",
    "self-declared",
    "third-party-attested",
    "multi-signed",
    "log-anchored",
];

/// `MARKER_ORDER.index(marker) >= MARKER_ORDER.index(minimum)` — py
/// `marker_at_least`. Unknown markers compare as the weakest grade.
pub fn marker_at_least(marker: &str, minimum: &str) -> bool {
    let grade = |m: &str| MARKER_ORDER.iter().position(|x| *x == m).unwrap_or(0);
    grade(marker) >= grade(minimum)
}

/// `fail` > `degraded` > `pass` — py `combine_outcome`.
pub fn combine_outcome(outcomes: &[&str]) -> &'static str {
    if outcomes.contains(&"fail") {
        "fail"
    } else if outcomes.contains(&"degraded") {
        "degraded"
    } else {
        "pass"
    }
}

/// I13: stale/offline data degrades explicitly, never silently passes
/// — py `outcome_for_freshness`. An unknown freshness (no requirement
/// declared) is informational.
pub fn outcome_for_freshness(freshness: Freshness) -> &'static str {
    match freshness {
        Freshness::Fresh => "pass",
        Freshness::Stale => "degraded",
        Freshness::Unknown => "pass",
    }
}

/// Freshness of the evidence's as-of stamp relative to `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
    Unknown,
}

impl Freshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
            Freshness::Unknown => "unknown",
        }
    }
}

/// Parse the ISO 8601 duration subset the py core accepts
/// (`PnDTnHnMnS`) into milliseconds. Malformed budgets read as
/// *unknown* freshness, exactly as the NaN path in py `duration_to_ms`.
pub fn duration_to_ms(duration: &str) -> Option<f64> {
    let body = duration.strip_prefix('P')?;
    let (days, time) = match body.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (body, None),
    };
    if days.is_empty() && time.is_none() {
        return None;
    }
    // The day component is `nD` (the literal D is mandatory in the py
    // grammar when the component is present).
    let days = if days.is_empty() {
        ""
    } else {
        days.strip_suffix('D')?
    };
    if !days.is_empty() && !days.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut ms = if days.is_empty() {
        0.0
    } else {
        days.parse::<f64>().ok()? * 86_400_000.0
    };
    if let Some(time) = time {
        // nHnMn(.s)S in order; each unit at most once.
        let mut rest = time;
        for (suffix, unit_ms) in [("H", 3_600_000.0), ("M", 60_000.0)] {
            if rest.is_empty() {
                break;
            }
            match rest.split_once(suffix) {
                Some((n, r)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
                    ms += n.parse::<f64>().ok()? * unit_ms;
                    rest = r;
                }
                _ => continue,
            }
        }
        if let Some((n, r)) = rest.split_once('S') {
            if r.is_empty() && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                ms += n.parse::<f64>().ok()? * 1000.0;
                rest = "";
            }
        }
        if !rest.is_empty() {
            return None;
        }
    }
    Some(ms)
}

/// Freshness of the evidence's as-of stamp relative to `now` — py
/// `assess_freshness`: no requirement declared ⇒ unknown; otherwise
/// fresh iff `now - as_of <= budget`.
pub fn assess_freshness(
    as_of: Option<Timestamp>,
    required: Option<&str>,
    now: Timestamp,
) -> Freshness {
    let Some(required) = required else {
        return Freshness::Unknown;
    };
    let (Some(as_of), Some(budget_ms)) = (as_of, duration_to_ms(required)) else {
        return Freshness::Unknown;
    };
    let age_ms = (now.secs as f64 - as_of.secs as f64) * 1000.0;
    if age_ms <= budget_ms {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}

// ---------------------------------------------------------------------------
// Findings + coverage (model.py, rendered via verify.py)
// ---------------------------------------------------------------------------

/// One finding: severity (`info`|`warning`|`error`), code, message.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl Finding {
    fn new(severity: &'static str, code: &'static str, message: impl Into<String>) -> Finding {
        Finding {
            severity,
            code,
            message: message.into(),
        }
    }

    fn to_dict(&self) -> Value {
        json!({"severity": self.severity, "code": self.code, "message": self.message})
    }
}

/// Verification is coverage-based, not boolean (I9) — py
/// `CoverageReport`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CoverageReport {
    pub checks: usize,
    pub passed: usize,
    pub signatures_total: usize,
    pub signatures_verified: usize,
    pub signatures_failed: usize,
    pub signatures_unsupported: usize,
    pub anchor_coverage: f64,
    pub trust_coverage: f64,
}

impl CoverageReport {
    /// The py wire shape (`CoverageReport.to_dict`).
    pub fn to_dict(&self) -> Value {
        json!({
            "checks": self.checks,
            "passed": self.passed,
            "signatures": {
                "total": self.signatures_total,
                "verified": self.signatures_verified,
                "failed": self.signatures_failed,
                "unsupported": self.signatures_unsupported,
            },
            "anchorCoverage": self.anchor_coverage,
            "trustCoverage": self.trust_coverage,
        })
    }
}

/// The verdict — py `Verdict`, wire shape via `Verdict.to_dict`.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub reading: &'static str,
    pub outcome: &'static str,
    pub freshness: Freshness,
    pub coverage: CoverageReport,
    pub findings: Vec<Finding>,
    pub as_of: Timestamp,
    pub achieved_marker: &'static str,
}

impl Verdict {
    pub fn to_dict(&self) -> Value {
        json!({
            "reading": self.reading,
            "outcome": self.outcome,
            "freshness": self.freshness.as_str(),
            "coverage": self.coverage.to_dict(),
            "findings": self.findings.iter().map(Finding::to_dict).collect::<Vec<_>>(),
            "asOf": self.as_of.to_string(),
            "achievedMarker": self.achieved_marker,
        })
    }
}

// ---------------------------------------------------------------------------
// Crypto slots (verify.py crypto.ts port)
// ---------------------------------------------------------------------------

/// Raw public key as carried in pre-cached trust anchors — py
/// `PublicKeyMaterial`. The gateway's anchors are Ed25519 raw keys.
#[derive(Debug, Clone)]
pub struct PublicKeyMaterial {
    /// `"spki"`-style raw bytes (the unidpp-signatif keyring hex).
    pub bytes: Vec<u8>,
}

/// The input to one signature verification — py `SignatureInput`. The
/// payload is the event's canonical body (the signed payload).
pub struct SignatureInput<'a> {
    pub suite: &'a str,
    pub payload: &'a [u8],
    pub signature: &'a [u8],
    pub key_id: &'a str,
    pub anchor: &'a PublicKeyMaterial,
}

/// Pluggable crypto slot (I9 multi-suite). A slot whose `supported` is
/// `false` is a placeholder: it advertises its suites so framings route
/// to it, but every verification reports *unsupported* — the verdict
/// degrades (warning), never silently passes.
pub trait CryptoSlot: Send + Sync {
    fn suites(&self) -> &'static [&'static str];
    fn supported(&self) -> bool {
        true
    }
    fn reason(&self) -> Option<String> {
        None
    }
    fn verify(&self, framing: &SignatureInput<'_>) -> bool;
}

/// ECDSA placeholder — the port of py `EcdsaNoneSlot`. No profile-bound
/// ECDSA binding is registered in the gateway, so ECDSA framings
/// degrade exactly as the multi-suite model demands.
pub struct EcdsaNoneSlot;

const ECDSA_SUITES: &[&str] = &["ecdsa-p256-sha256", "ecdsa-p384-sha384"];

impl CryptoSlot for EcdsaNoneSlot {
    fn suites(&self) -> &'static [&'static str] {
        ECDSA_SUITES
    }
    fn supported(&self) -> bool {
        false
    }
    fn reason(&self) -> Option<String> {
        Some(
            "ECDSA verification not linked in the stdlib-only core; \
             register a profile-bound suite binding"
                .to_string(),
        )
    }
    fn verify(&self, _framing: &SignatureInput<'_>) -> bool {
        false
    }
}

/// Real Ed25519 slot over `unidpp-signatif` — the suite the issuer
/// signs events with. A genuine verifier demonstrating slot
/// pluggability (the role the py `HmacSha256Slot` plays for the py
/// test runs, exercised with the production suite instead).
pub struct Ed25519Slot;

impl CryptoSlot for Ed25519Slot {
    fn suites(&self) -> &'static [&'static str] {
        &["ed25519"]
    }
    fn verify(&self, framing: &SignatureInput<'_>) -> bool {
        let Ok(suite) = unidpp_signatif::sign::Suite::parse_token(framing.suite) else {
            return false;
        };
        let Ok(key_id) = unidpp_signatif::keyring::KeyId::new(framing.key_id) else {
            return false;
        };
        let slot = unidpp_signatif::sign::SignatureSlot {
            suite,
            key_id,
            signature: Some(framing.signature.to_vec()),
        };
        let Ok(public) = unidpp_signatif::keyring::PublicKey::from_bytes(&framing.anchor.bytes)
        else {
            return false;
        };
        slot.verify(
            unidpp_signatif::sign::SigningDomain::ArtifactEvent,
            framing.payload,
            &public,
        )
        .is_ok()
    }
}

/// Slot registry: profile acceptance policies check `suits(suite)` —
/// py `CryptoSlots`.
#[derive(Default)]
pub struct CryptoSlots {
    slots: HashMap<String, std::sync::Arc<dyn CryptoSlot>>,
}

impl CryptoSlots {
    pub fn register(&mut self, slot: std::sync::Arc<dyn CryptoSlot>) {
        for suite in slot.suites() {
            self.slots.insert(suite.to_string(), slot.clone());
        }
    }

    pub fn suits(&self, suite: &str) -> bool {
        self.slots.contains_key(suite)
    }

    pub fn get(&self, suite: &str) -> Option<std::sync::Arc<dyn CryptoSlot>> {
        self.slots.get(suite).cloned()
    }
}

/// The gateway's default registry: the ECDSA placeholder plus the real
/// Ed25519 slot. Suites with no registered binding (e.g. `sm2`,
/// `ml-dsa-*`) take the py `slot is None` path: warning +
/// `suite-unsupported` + degraded.
pub fn default_slots() -> CryptoSlots {
    let mut slots = CryptoSlots::default();
    slots.register(std::sync::Arc::new(EcdsaNoneSlot));
    slots.register(std::sync::Arc::new(Ed25519Slot));
    slots
}

// ---------------------------------------------------------------------------
// The verification pipeline (verify.py verify_tier_a_pack, over the
// passport document)
// ---------------------------------------------------------------------------

/// Verification options — py `VerifyOptions` (revocation readings are
/// carried by the downstream signatif layer; the gateway renders, it
/// does not adjudicate revocation).
pub struct VerifyOptions<'a> {
    /// Pre-cached trust anchors by key id.
    pub anchors: HashMap<String, PublicKeyMaterial>,
    /// Slot registry (defaults to [`default_slots`]).
    pub slots: Option<CryptoSlots>,
    /// Verification reading (`current-state` default, as py).
    pub reading: &'static str,
    /// Tainted passport ids — a graph event; fails under every reading.
    pub tainted_passport_ids: &'a [String],
    /// Required freshness (ISO 8601 duration); `None` = undeclared.
    pub required_freshness: Option<&'a str>,
    /// Minimum trust marker (`unsigned` = no requirement).
    pub minimum_marker: &'static str,
    /// The verification instant.
    pub now: Timestamp,
}

impl Default for VerifyOptions<'_> {
    fn default() -> Self {
        VerifyOptions {
            anchors: HashMap::new(),
            slots: None,
            reading: "current-state",
            tainted_passport_ids: &[],
            required_freshness: None,
            minimum_marker: "unsigned",
            now: Timestamp::now(),
        }
    }
}

/// Validate the document's evidence against pre-cached trust anchors,
/// check validity/freshness, apply taint semantics, and produce a
/// verdict with a coverage report. Stale/offline data degrades
/// explicitly — never silently passes.
pub fn verify_passport(document: &Passport, options: &VerifyOptions<'_>) -> Verdict {
    let now = options.now;
    let mut findings: Vec<Finding> = Vec::new();
    let mut outcomes: Vec<&str> = Vec::new();

    // Schema leg: satisfied by construction — the document parsed into
    // the typed core (the py schema leg's guarantee, held by the type
    // system here). Counts as one passed check, as in py.
    let mut checks = 1usize;
    let mut passed = 1usize;

    // Taint is a graph event: fails under every reading.
    if options
        .tainted_passport_ids
        .iter()
        .any(|t| t == document.passport_id.as_str())
    {
        findings.push(Finding::new(
            "error",
            "tainted",
            format!("passport {} is tainted", document.passport_id.as_str()),
        ));
        outcomes.push("fail");
    }

    // Validity window.
    checks += 1;
    if now < document.validity.from || document.validity.to.map(|to| now > to).unwrap_or(false) {
        findings.push(Finding::new(
            "error",
            "validity-window",
            format!(
                "document outside validity window [{}, {}]",
                document.validity.from,
                document
                    .validity
                    .to
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "open".to_string())
            ),
        ));
        outcomes.push("fail");
    } else {
        passed += 1;
    }

    // Freshness of the evidence relative to `now`; a critical safety
    // (recall) flag cannot silently degrade: recall evidence that is
    // stale fails outright.
    let recall = document.log.safety_flag() != unidpp_event::SafetyFlag::None;
    let freshness = assess_freshness(
        document.log.last_event_at(),
        options.required_freshness,
        now,
    );
    if recall && freshness == Freshness::Stale {
        findings.push(Finding::new(
            "error",
            "recall-stale",
            "recall flag present but data is stale — cannot pass",
        ));
        outcomes.push("fail");
    }
    outcomes.push(outcome_for_freshness(freshness));
    checks += 1;
    if freshness == Freshness::Fresh {
        passed += 1;
    }

    // Signature framings: the recorded event signatures, verified
    // against the cached anchors over each event's canonical body.
    let fresh_registry;
    let slots = match options.slots.as_ref() {
        Some(slots) => slots,
        None => {
            fresh_registry = default_slots();
            &fresh_registry
        }
    };
    let mut verified = 0usize;
    let mut failed = 0usize;
    let mut unsupported = 0usize;
    let mut anchored_keys = 0usize;
    let mut strongest = "unsigned";

    for framing in &document.event_signatures {
        let sealed = document
            .log
            .sealed()
            .get(framing.seq as usize)
            .filter(|s| s.event.seq == framing.seq);
        let Some(sealed) = sealed else {
            failed += 1;
            findings.push(Finding::new(
                "error",
                "signature-invalid",
                format!(
                    "signature names seq {} but no such event is sealed",
                    framing.seq
                ),
            ));
            outcomes.push("fail");
            continue;
        };
        let payload = sealed.event.canonical_body().unwrap_or_else(|_| Vec::new());
        let signature = match unidpp_cli::encoding::hex_decode(&framing.signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                failed += 1;
                findings.push(Finding::new(
                    "error",
                    "signature-invalid",
                    format!(
                        "signature by {} ({}) is not valid hex",
                        framing.key_id, framing.suite
                    ),
                ));
                outcomes.push("fail");
                continue;
            }
        };
        let Some(slot) = slots.get(&framing.suite) else {
            unsupported += 1;
            findings.push(Finding::new(
                "warning",
                "suite-unsupported",
                format!(
                    "no crypto slot for suite {} (profile-bound suite; register the binding)",
                    framing.suite
                ),
            ));
            outcomes.push("degraded");
            continue;
        };
        if !slot.supported() {
            unsupported += 1;
            let reason = slot
                .reason()
                .unwrap_or_else(|| "slot reports unsupported".into());
            findings.push(Finding::new(
                "warning",
                "suite-unsupported",
                format!("suite {} unsupported: {reason}", framing.suite),
            ));
            outcomes.push("degraded");
            continue;
        }
        let Some(anchor) = options.anchors.get(&framing.key_id) else {
            failed += 1;
            findings.push(Finding::new(
                "error",
                "key-unanchored",
                format!("keyId {} not in cached trust anchors", framing.key_id),
            ));
            outcomes.push("fail");
            continue;
        };
        anchored_keys += 1;
        checks += 1;
        let input = SignatureInput {
            suite: &framing.suite,
            payload: &payload,
            signature: &signature,
            key_id: &framing.key_id,
            anchor,
        };
        if slot.verify(&input) {
            verified += 1;
            passed += 1;
            // py rule verbatim: symmetric test suites self-declare;
            // every real asymmetric suite third-party-attests.
            let marker = if framing.suite.contains("testmac") {
                "self-declared"
            } else {
                "third-party-attested"
            };
            if strongest == "unsigned" || marker_at_least(marker, strongest) {
                strongest = marker;
            }
        } else {
            failed += 1;
            findings.push(Finding::new(
                "error",
                "signature-invalid",
                format!(
                    "signature by {} ({}) failed verification",
                    framing.key_id, framing.suite
                ),
            ));
            outcomes.push("fail");
        }
    }

    let minimum = options.minimum_marker;
    let trust_coverage = if minimum == "unsigned" || marker_at_least(strongest, minimum) {
        1.0
    } else {
        0.0
    };
    if trust_coverage < 1.0 {
        findings.push(Finding::new(
            "warning",
            "below-minimum-marker",
            format!("achieved {strongest}, below required {minimum}"),
        ));
    }

    let total = document.event_signatures.len();
    let coverage = CoverageReport {
        checks,
        passed,
        signatures_total: total,
        signatures_verified: verified,
        signatures_failed: failed,
        signatures_unsupported: unsupported,
        anchor_coverage: if total == 0 {
            0.0
        } else {
            anchored_keys as f64 / total as f64
        },
        trust_coverage,
    };

    Verdict {
        reading: options.reading,
        outcome: combine_outcome(&outcomes),
        freshness,
        coverage,
        findings,
        as_of: now,
        achieved_marker: strongest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_cli::passport::{EventSignature, MintOptions, Passport};
    use unidpp_event::{EventPayload, EventType, TypedEvent};
    use unidpp_model::TrustMarker;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    fn doc() -> Passport {
        let mut p = Passport::mint(MintOptions {
            id: "gtin:4006381333931".into(),
            granularity: None,
            type_ref: None,
            capability: "S1".into(),
            eo_id: Some("eo-t".into()),
            resolver_uri: None,
            passport_id: Some("urn:unidpp:passport:v-t".into()),
            valid_from: Some(ts("2020-01-01T00:00:00Z")),
            valid_to: Some(ts("2040-01-01T00:00:00Z")),
        })
        .unwrap();
        let e = TypedEvent::new(
            0,
            ts("2026-06-12T16:31:00Z"),
            "issuing authority",
            "eo-t",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::Attested,
        )
        .unwrap();
        p.log.append(e, None, None).unwrap();
        p
    }

    fn opts<'a>() -> VerifyOptions<'a> {
        VerifyOptions {
            now: ts("2026-09-07T12:00:00Z"),
            ..VerifyOptions::default()
        }
    }

    #[test]
    fn marker_ladder_and_outcomes() {
        assert!(marker_at_least("third-party-attested", "self-declared"));
        assert!(!marker_at_least("unsigned", "self-declared"));
        assert_eq!(combine_outcome(&["pass", "degraded", "pass"]), "degraded");
        assert_eq!(combine_outcome(&["degraded", "fail"]), "fail");
        assert_eq!(combine_outcome(&["pass"]), "pass");
        assert_eq!(outcome_for_freshness(Freshness::Stale), "degraded");
        assert_eq!(outcome_for_freshness(Freshness::Unknown), "pass");
    }

    #[test]
    fn durations_parse_like_the_py_regex() {
        assert_eq!(duration_to_ms("PT1H"), Some(3_600_000.0));
        assert_eq!(duration_to_ms("P1D"), Some(86_400_000.0));
        assert_eq!(duration_to_ms("P2DT3H4M5.5S"), Some(183_845_500.0));
        assert_eq!(duration_to_ms("P"), None);
        assert_eq!(duration_to_ms("nonsense"), None);
        assert_eq!(duration_to_ms("PT1X"), None);
    }

    #[test]
    fn freshness_ladder() {
        let now = ts("2026-09-07T12:00:00Z");
        assert_eq!(
            assess_freshness(Some(ts("2026-09-07T11:00:00Z")), Some("PT2H"), now),
            Freshness::Fresh
        );
        assert_eq!(
            assess_freshness(Some(ts("2026-09-06T11:00:00Z")), Some("PT2H"), now),
            Freshness::Stale
        );
        // Future-dated evidence reads fresh (non-negative age budget).
        assert_eq!(
            assess_freshness(Some(ts("2027-01-01T00:00:00Z")), Some("PT2H"), now),
            Freshness::Fresh
        );
        assert_eq!(assess_freshness(Some(now), None, now), Freshness::Unknown);
        assert_eq!(
            assess_freshness(Some(now), Some("wat"), now),
            Freshness::Unknown
        );
    }

    #[test]
    fn clean_document_passes_with_unknown_freshness() {
        let v = verify_passport(&doc(), &opts());
        assert_eq!(v.outcome, "pass");
        assert_eq!(v.freshness, Freshness::Unknown);
        assert_eq!(v.achieved_marker, "unsigned");
        assert!(v.findings.is_empty());
        assert_eq!(v.coverage.checks, 3); // schema + validity + freshness
        assert_eq!(v.coverage.passed, 2); // unknown freshness does not count as passed
        assert_eq!(v.coverage.signatures_total, 0);
    }

    #[test]
    fn stale_evidence_degrades() {
        let mut o = opts();
        o.required_freshness = Some("PT1H");
        let v = verify_passport(&doc(), &o);
        assert_eq!(v.outcome, "degraded");
        assert_eq!(v.freshness, Freshness::Stale);
        assert!(v.findings.is_empty(), "stale alone is not a finding");
    }

    #[test]
    fn outside_validity_window_fails() {
        let mut o = opts();
        o.now = ts("2050-01-01T00:00:00Z");
        let v = verify_passport(&doc(), &o);
        assert_eq!(v.outcome, "fail");
        assert!(v
            .findings
            .iter()
            .any(|f| f.code == "validity-window" && f.severity == "error"));
    }

    #[test]
    fn taint_fails_under_every_reading() {
        let mut o = opts();
        let tainted = ["urn:unidpp:passport:v-t".to_string()];
        o.tainted_passport_ids = &tainted;
        let v = verify_passport(&doc(), &o);
        assert_eq!(v.outcome, "fail");
        assert!(v.findings.iter().any(|f| f.code == "tainted"));
    }

    #[test]
    fn unanchored_signature_fails_and_unsupported_degrades() {
        let mut d = doc();
        d.event_signatures.push(EventSignature {
            seq: 0,
            suite: "ed25519".into(),
            key_id: "k-missing".into(),
            signature: "00".repeat(64),
        });
        let v = verify_passport(&d, &opts());
        assert_eq!(v.outcome, "fail");
        assert!(v.findings.iter().any(|f| f.code == "key-unanchored"));

        let mut d2 = doc();
        d2.event_signatures.push(EventSignature {
            seq: 0,
            suite: "ecdsa-p256-sha256".into(),
            key_id: "k-any".into(),
            signature: "00".repeat(64),
        });
        let v2 = verify_passport(&d2, &opts());
        assert_eq!(v2.outcome, "degraded");
        assert_eq!(v2.coverage.signatures_unsupported, 1);
        assert!(v2
            .findings
            .iter()
            .any(|f| f.code == "suite-unsupported" && f.severity == "warning"));

        let mut d3 = doc();
        d3.event_signatures.push(EventSignature {
            seq: 0,
            suite: "sm2-sm3".into(),
            key_id: "k-any".into(),
            signature: "00".repeat(64),
        });
        let v3 = verify_passport(&d3, &opts());
        assert_eq!(v3.outcome, "degraded");
        assert_eq!(v3.coverage.signatures_unsupported, 1);
        assert_eq!(v3.coverage.signatures_failed, 0);
    }

    #[test]
    fn minimum_marker_below_warns() {
        let mut o = opts();
        o.minimum_marker = "third-party-attested";
        let v = verify_passport(&doc(), &o);
        assert_eq!(v.outcome, "pass"); // below-minimum is a warning, not a fail
        assert_eq!(v.coverage.trust_coverage, 0.0);
        assert!(v
            .findings
            .iter()
            .any(|f| f.code == "below-minimum-marker" && f.severity == "warning"));
    }

    #[test]
    fn ghost_signature_seq_fails() {
        let mut d = doc();
        d.event_signatures.push(EventSignature {
            seq: 9,
            suite: "ed25519".into(),
            key_id: "k-x".into(),
            signature: "00".repeat(64),
        });
        let v = verify_passport(&d, &opts());
        assert_eq!(v.outcome, "fail");
        assert_eq!(v.coverage.signatures_failed, 1);
    }

    #[test]
    fn real_ed25519_slot_verifies_and_catches_tampering() {
        let key = unidpp_signatif::keyring::KeyPair::seeded(
            unidpp_signatif::sign::Suite::Ed25519,
            b"gateway-verdict-test",
        )
        .unwrap();
        let mut d = doc();
        let body = d.log.sealed()[0].event.canonical_body().unwrap();
        let slot = unidpp_signatif::sign::SignatureSlot::sign(
            &key,
            unidpp_signatif::sign::SigningDomain::ArtifactEvent,
            &body,
        )
        .unwrap();
        let signature = slot.signature.clone().unwrap();
        d.event_signatures.push(EventSignature {
            seq: 0,
            suite: "ed25519".into(),
            key_id: key.key_id().as_str().to_string(),
            signature: unidpp_cli::encoding::hex_encode(&signature),
        });
        let mut o = opts();
        o.anchors.insert(
            key.key_id().as_str().to_string(),
            PublicKeyMaterial {
                bytes: key.public().as_bytes().to_vec(),
            },
        );
        let v = verify_passport(&d, &o);
        assert_eq!(v.outcome, "pass");
        assert_eq!(v.coverage.signatures_verified, 1);
        assert_eq!(v.achieved_marker, "third-party-attested");
        assert_eq!(v.coverage.anchor_coverage, 1.0);

        // Tampered signature fails real verification.
        d.event_signatures[0].signature = unidpp_cli::encoding::hex_encode(&[0u8; 64]);
        let v2 = verify_passport(&d, &o);
        assert_eq!(v2.outcome, "fail");
        assert_eq!(v2.coverage.signatures_failed, 1);
        assert_eq!(v2.achieved_marker, "unsigned");
    }

    #[test]
    fn verdict_wire_shape_matches_the_py_vocabulary() {
        let v = verify_passport(&doc(), &opts());
        let wire = v.to_dict();
        assert_eq!(wire["reading"], "current-state");
        assert_eq!(wire["outcome"], "pass");
        assert_eq!(wire["freshness"], "unknown");
        assert_eq!(wire["achievedMarker"], "unsigned");
        assert_eq!(wire["coverage"]["signatures"]["total"], 0);
        assert!(wire["asOf"].as_str().unwrap().ends_with('Z'));
    }
}
