//! UNTP ingest — the import direction of the S12 seam.
//!
//! [`crate::untp::render_triad`] projects a UniDPP passport to the UNTP
//! verifiable-credential triad; this module runs the projection in
//! reverse: a UNTP passport VC (bare, or wrapped in the triad this
//! gateway itself renders) is parsed with the same identifier rules
//! (`parse_stub` semantics, reused verbatim), minted as a neutral-core
//! passport with a **deterministic identity** — one subject, one
//! identity (I1), so re-ingesting the same triad matches instead of
//! duplicating — and its conformity credentials land as profile
//! bindings.
//!
//! Honesty rules: an identifier scheme with no C8 mapping degrades
//! explicitly (nothing is minted under a guessed scheme); the imported
//! passport's event log is empty (its events live in the source regime
//! — the ingest receipt records the origin and the commitment over the
//! imported stub); warnings are reported, never swallowed.

use std::collections::HashMap;

use serde_json::{json, Value};
use unidpp_cli::passport::{MintOptions, Passport};
use unidpp_model::{sha256, ProductIdentifier, Timestamp};

use crate::source::{GatewayPassport, ProfileRef};
use crate::untp::{core_identifier_value, scheme_token};

/// The outcome of one ingest call.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    /// What happened: freshly imported, or matched an earlier import
    /// of the same subject identity.
    pub status: IngestStatus,
    /// The minted (or previously minted) core passport.
    pub passport: GatewayPassport,
    /// Conformity credentials that landed as profile bindings.
    pub profiles: Vec<ProfileRef>,
    /// The import receipt (origin identifiers, commitment, counts).
    pub receipt: Value,
}

/// Whether an ingest minted or matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestStatus {
    /// First import of this subject identity: a core passport was
    /// minted.
    Imported,
    /// The subject identity was already imported: the existing core
    /// passport is returned unchanged (idempotent).
    Matched,
}

impl IngestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            IngestStatus::Imported => "imported",
            IngestStatus::Matched => "matched",
        }
    }
}

/// The store of ingested passports, keyed by passport id.
#[derive(Default)]
pub struct IngestStore {
    entries: HashMap<String, GatewayPassport>,
    receipts: HashMap<String, Value>,
}

impl IngestStore {
    pub fn new() -> IngestStore {
        IngestStore::default()
    }

    /// Ingest a UNTP body: the rendered triad (`{passport, conformity,
    /// link, ...}`), a bare passport VC, or `{"stub": {...}}`. Returns
    /// the outcome, or an explicit degradation reason.
    pub fn ingest(&mut self, body: &Value, now: Timestamp) -> Result<IngestOutcome, String> {
        let stub = extract_stub(body)?;
        let conformity = extract_conformity(body);
        let link = body.get("link");

        let (identity, warnings) = parse_identity(stub)?;
        let passport_id = derived_passport_id(&identity);

        if let Some(existing) = self.entries.get(&passport_id) {
            return Ok(IngestOutcome {
                status: IngestStatus::Matched,
                passport: existing.clone(),
                profiles: profiles_of(existing),
                receipt: self
                    .receipts
                    .get(&passport_id)
                    .cloned()
                    .unwrap_or_else(|| json!({ "passport_id": passport_id })),
            });
        }

        let profiles = conformity_bindings(&conformity);
        let eo_id = stub
            .get("passportIssuer")
            .and_then(|i| i.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("urn:unidpp:import:untp")
            .to_string();
        let resolver_uri = link
            .and_then(|l| l.get("target"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let valid_from = stub
            .get("validFrom")
            .and_then(Value::as_str)
            .and_then(|s| Timestamp::parse(s).ok());
        let valid_to = stub
            .get("validUntil")
            .and_then(Value::as_str)
            .and_then(|s| Timestamp::parse(s).ok());

        let document = Passport::mint(MintOptions {
            id: identity.to_string(),
            granularity: None,
            type_ref: None,
            capability: "S1".to_string(),
            eo_id: Some(eo_id),
            resolver_uri,
            passport_id: Some(passport_id.clone()),
            valid_from,
            valid_to,
        })
        .map_err(|e| format!("mint failed for the imported identity: {e}"))?;

        let passport = GatewayPassport::fixture(document, profiles);
        let receipt = json!({
            "passport_id": passport_id,
            "source": {
                "regime": "untp",
                "stub_id": stub.get("id").and_then(Value::as_str),
                "identifier_scheme": scheme_uri_of(stub),
                "imported_at": now.to_string(),
            },
            "conformity_credentials": conformity.len(),
            "profile_bindings": passport.profiles.len(),
            "warnings": warnings,
            "commitment": sha256(&[stub.to_string().as_bytes()]).hex(),
        });
        self.entries.insert(passport_id, passport.clone());
        self.receipts.insert(
            passport.document.passport_id.as_str().to_string(),
            receipt.clone(),
        );
        Ok(IngestOutcome {
            status: IngestStatus::Imported,
            profiles: profiles_of(&passport),
            receipt,
            passport,
        })
    }

    /// Resolve an ingested passport by passport id or product identity
    /// (the same keys the fixture source answers).
    pub fn resolve(&self, id: &str) -> Option<&GatewayPassport> {
        self.entries.values().find(|p| {
            p.document.passport_id.as_str() == id || p.document.product_id.to_string() == id
        })
    }

    /// How many ingested passports the store holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The passport VC inside any accepted body shape.
fn extract_stub(body: &Value) -> Result<&Value, String> {
    if let Some(stub) = body.get("stub") {
        return Ok(stub);
    }
    if body.get("productIdentifiers").is_some() {
        return Ok(body);
    }
    if let Some(passport) = body.get("passport") {
        if passport.get("productIdentifiers").is_some() {
            return Ok(passport);
        }
    }
    Err("no UNTP passport VC found (expected {passport: {...productIdentifiers...}}, a bare passport VC, or {stub: {...}})".to_string())
}

fn extract_conformity(body: &Value) -> Vec<&Value> {
    body.get("conformity")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

/// Parse the subject identity from the first product identifier, using
/// the same scheme/value rules as the render direction. Unknown
/// schemes degrade explicitly — the caller reports, nothing mints.
fn parse_identity(stub: &Value) -> Result<(ProductIdentifier, Vec<String>), String> {
    let ids = stub
        .get("productIdentifiers")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "the passport VC carries no productIdentifiers".to_string())?;
    let raw = ids
        .first()
        .and_then(Value::as_object)
        .ok_or_else(|| "the first productIdentifier is malformed".to_string())?;
    let value = raw
        .get("value")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "the identifier carries no value".to_string())?;
    // The py adapter's default: an absent scheme reads as GS1.
    let scheme = raw
        .get("scheme")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("https://gs1.org/voc/");
    let token = scheme_token(scheme);
    let display = core_identifier_value(&token, value);
    let identity = ProductIdentifier::parse(&display).map_err(|_| {
        format!(
            "identifier scheme `{scheme}` (token `{token}`, value `{value}`) has no C8 \
             mapping onto the core identity table: nothing is minted under a guessed scheme \
             (record the scheme in the registry, then re-ingest)"
        )
    })?;
    let mut warnings = Vec::new();
    if ids.len() > 1 {
        warnings.push(format!(
            "{} additional product identifiers recorded in the receipt only (the core identity \
             is the first, per the render convention)",
            ids.len() - 1
        ));
    }
    Ok((identity, warnings))
}

/// Deterministic passport id from the subject identity alone: the same
/// subject maps to the same identity forever (I1) — a different stub
/// for the same product *matches* rather than duplicating.
fn derived_passport_id(identity: &ProductIdentifier) -> String {
    let digest = sha256(&[
        b"UNIDPP/GATEWAY/UNTP-INGEST|",
        identity.to_string().as_bytes(),
    ]);
    format!("urn:unidpp:passport:untp-{}", &digest.hex()[..12])
}

/// Conformity credentials → profile bindings: one binding per
/// credential that names a conformity standard.
fn conformity_bindings(conformity: &[&Value]) -> Vec<ProfileRef> {
    let mut bindings = Vec::new();
    for credential in conformity {
        let Some(subject) = credential.get("credentialSubject") else {
            continue;
        };
        let Some(named) = subject.get("conformity") else {
            continue;
        };
        let Some(id) = named.get("standard").and_then(Value::as_str) else {
            continue;
        };
        if id.trim().is_empty() {
            continue;
        }
        bindings.push(ProfileRef {
            id: id.trim().to_string(),
            version: named
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unversioned")
                .trim()
                .to_string(),
            effective_from: credential
                .get("validFrom")
                .and_then(Value::as_str)
                .and_then(|s| Timestamp::parse(s).ok()),
        });
    }
    bindings
}

fn profiles_of(passport: &GatewayPassport) -> Vec<ProfileRef> {
    passport.profiles.clone()
}

fn scheme_uri_of(stub: &Value) -> Option<&str> {
    stub.get("productIdentifiers")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|i| i.get("scheme"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_model::IdScheme;

    fn stub() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DigitalProductPassport"],
            "id": "https://example.org/passports/42",
            "passportIssuer": {"id": "https://example.org/docs/issuer", "name": "Example Issuer"},
            "validFrom": "2026-01-15T00:00:00Z",
            "productIdentifiers": [{
                "scheme": "https://ref.gs1.org/",
                "value": "(01)4006381333931(21)SN7"
            }]
        })
    }

    fn now() -> Timestamp {
        Timestamp::from_secs(1_800_000_000)
    }

    #[test]
    fn triad_ingests_with_profile_bindings_and_receipt() {
        let mut store = IngestStore::new();
        let triad = json!({
            "passport": stub(),
            "conformity": [
                json!({
                    "type": ["VerifiableCredential", "DigitalConformityCredential"],
                    "credentialSubject": {
                        "type": "ConformityAttestation",
                        "conformity": {"standard": "urn:unidpp:profile:eu-espr-battery-v3", "version": "3.0"},
                    },
                    "validFrom": "2026-01-15T00:00:00Z",
                })
            ],
            "link": {"linkType": "untp-dpp", "target": "https://example.org/r/42"},
        });
        let outcome = store.ingest(&triad, now()).unwrap();
        assert_eq!(outcome.status, IngestStatus::Imported);
        assert_eq!(outcome.profiles.len(), 1);
        assert_eq!(
            outcome.profiles[0].id,
            "urn:unidpp:profile:eu-espr-battery-v3"
        );
        assert_eq!(outcome.profiles[0].version, "3.0");
        assert!(outcome
            .passport
            .document
            .passport_id
            .as_str()
            .starts_with("urn:unidpp:passport:untp-"));
        assert_eq!(outcome.passport.document.product_id.scheme, IdScheme::Sgtin);
        assert_eq!(outcome.receipt["conformity_credentials"], 1);
        assert!(outcome.receipt["commitment"].as_str().unwrap().len() == 64);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn re_ingest_matches_and_a_different_stub_for_the_same_subject_matches_too() {
        let mut store = IngestStore::new();
        let outcome = store.ingest(&stub(), now()).unwrap();
        let id = outcome.passport.document.passport_id.as_str().to_string();
        // Same triad again: matched, no duplicate.
        let again = store.ingest(&stub(), now()).unwrap();
        assert_eq!(again.status, IngestStatus::Matched);
        assert_eq!(again.passport.document.passport_id.as_str(), id);
        assert_eq!(store.len(), 1);
        // A different stub id for the SAME subject: still the same
        // core identity (I1) — matched.
        let mut other = stub();
        other["id"] = json!("https://other.example.org/passport/7");
        let matched = store.ingest(&other, now()).unwrap();
        assert_eq!(matched.status, IngestStatus::Matched);
        assert_eq!(matched.passport.document.passport_id.as_str(), id);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn unknown_scheme_degrades_explicitly() {
        let mut store = IngestStore::new();
        let mut exotic = stub();
        exotic["productIdentifiers"] = json!([{
            "scheme": "https://example.org/schemes/exotic/",
            "value": "XYZ-42"
        }]);
        let err = store.ingest(&exotic, now()).unwrap_err();
        assert!(err.contains("no C8 mapping"), "{err}");
        assert!(store.is_empty());
    }

    #[test]
    fn malformed_inputs_are_rejected_with_reasons() {
        let mut store = IngestStore::new();
        assert!(store.ingest(&json!({}), now()).is_err());
        let mut no_ids = stub();
        no_ids["productIdentifiers"] = json!([]);
        assert!(store.ingest(&no_ids, now()).is_err());
        let mut no_value = stub();
        no_value["productIdentifiers"] = json!([{"scheme": "https://ref.gs1.org/"}]);
        assert!(store.ingest(&no_value, now()).is_err());
    }

    #[test]
    fn resolve_answers_by_passport_id_and_product_id() {
        let mut store = IngestStore::new();
        let outcome = store.ingest(&stub(), now()).unwrap();
        let by_passport = store
            .resolve(outcome.passport.document.passport_id.as_str())
            .unwrap();
        assert_eq!(
            store
                .resolve(&outcome.passport.document.product_id.to_string())
                .unwrap()
                .document
                .passport_id,
            by_passport.document.passport_id
        );
        assert!(store.resolve("urn:unidpp:passport:none").is_none());
    }

    #[test]
    fn bare_stub_and_wrapped_stub_shapes_both_ingest() {
        let mut store = IngestStore::new();
        let a = store.ingest(&stub(), now()).unwrap();
        let mut wrapped = json!({});
        wrapped["stub"] = stub();
        // Same subject → matched even via the other shape.
        let b = store.ingest(&wrapped, now()).unwrap();
        assert_eq!(b.status, IngestStatus::Matched);
        assert_eq!(
            a.passport.document.passport_id,
            b.passport.document.passport_id
        );
    }
}
