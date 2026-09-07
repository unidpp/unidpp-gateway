//! The UNTP binding — a bidirectional port of
//! `unidpp-py/unidpp/adapters/untp.py` (the semantics source).
//!
//! - [`render_triad`]: the gateway's deliverable — a UniDPP passport
//!   rendered as a **UNTP verifiable-credential triad**: the Digital
//!   Product Passport VC (the py stub shape, so any UNTP stub consumer
//!   parses it), the DigitalConformityCredentials (profile bindings +
//!   the log's E14 inspection stamps), and the link-resolver entry
//!   (DLR shape: linkType/target plus the log-head anchor).
//! - [`parse_stub`]: the import direction, the faithful port of the py
//!   `parse_untp_stub` (scheme mapping, identifier extraction, issuer
//!   and validity reads, standardsConformance → profile bindings,
//!   commitment-anchored event-log pointer). The gateway keeps it so
//!   the round-trip — render then re-parse — is provable in tests and
//!   available to future ingest paths.
//!
//! Mapping notes (port of the py `_SCHEME_MAP` and back):
//!
//! | py scheme token | UNTP scheme URI | core `IdScheme` |
//! |---|---|---|
//! | `gs1` | `https://gs1.org/voc/` (also `id.gs1.org`/`ref.gs1.org`/`urn:epc:id:`) | `gtin`/`sgtin` |
//! | `iso-15459` | `https://unidpp.org/id/` (also `https://www.w3.org/ns/`) | `cpid` |
//!
//! The py model's `iso-15459` token and the Rust core's `cpid` scheme
//! denote the same thing (ISO/IEC 15459 URN identity); the Rust port
//! maps to the core vocabulary. GS1 values use the UNTP parenthesized
//! application-identifier form (`(01)0950…`); the parser accepts both
//! that and the core display form (`01+…`).

use serde_json::{json, Value};
use unidpp_event::EventPayload;
use unidpp_model::{Granularity, IdScheme, ProductIdentifier, Timestamp};

use crate::canonical::commitment;
use crate::source::GatewayPassport;
use crate::verdict::{self, VerifyOptions};

/// The registered render profile (a C4 protocol rendering is a
/// profile, not a fork of the core).
pub const UNTP_PROFILE: &str = "urn:unidpp:profile:render:untp";

/// UNTP scheme URI for a core scheme (inverse of the py `_SCHEME_MAP`).
pub fn scheme_uri(scheme: &IdScheme) -> String {
    match scheme {
        IdScheme::Gtin | IdScheme::Sgtin | IdScheme::Gsrn | IdScheme::Gln => {
            "https://gs1.org/voc/".to_string()
        }
        IdScheme::Cpid => "https://unidpp.org/id/".to_string(),
        other => other.as_str(),
    }
}

/// Core scheme token for a UNTP scheme URI (the py `_SCHEME_MAP`
/// direction, mapped into the core vocabulary).
pub fn scheme_token(uri: &str) -> String {
    match uri {
        "https://gs1.org/voc/" | "https://id.gs1.org/" | "https://ref.gs1.org/" | "urn:epc:id:" => {
            "gtin".to_string()
        }
        "https://www.w3.org/ns/" | "https://unidpp.org/id/" => "cpid".to_string(),
        other => other.to_string(), // registry extension point
    }
}

/// The UNTP identifier value: GS1-family identifiers in the
/// parenthesized application-identifier form, everything else in the
/// core display form.
pub fn untp_identifier_value(id: &ProductIdentifier) -> String {
    match id.scheme {
        IdScheme::Gtin | IdScheme::Sgtin => {
            let mut value = format!("(01){}", id.key);
            if let Some(lot) = &id.lot {
                value.push_str(&format!("(10){lot}"));
            }
            if let Some(serial) = &id.serial {
                value.push_str(&format!("(21){serial}"));
            }
            value
        }
        _ => id.to_string(),
    }
}

/// Normalize a UNTP identifier value back to the core display form
/// (accepts both `(01)x` and `01+x` element strings and bare keys).
fn core_identifier_value(scheme_token: &str, value: &str) -> String {
    if let Some(key) = value.strip_prefix("(01)") {
        let mut display = format!("01+{key}");
        display = display.replace("(10)", "+10+").replace("(21)", "+21+");
        return display;
    }
    if scheme_token == "gtin" && !value.contains('+') {
        return format!("01+{value}");
    }
    value.to_string()
}

/// Render the verifiable-credential triad plus the py-adapter verdict
/// (the `verify.py` rule ladder, ported in [`crate::verdict`]).
pub fn render_triad(
    p: &GatewayPassport,
    now: Timestamp,
    required_freshness: Option<&str>,
) -> Value {
    let document = &p.document;
    let subject = &document.product_id;

    let mut passport_vc = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://ref.gs1.org/gs1/voc/"
        ],
        // The py stub parser reads `type` and requires "passport" in
        // it (case-insensitive) — both VC types satisfy that.
        "type": ["VerifiableCredential", "DigitalProductPassport"],
        "id": document.passport_id.as_str(),
        "issuer": {"id": document.eo_id, "name": document.eo_id},
        "validFrom": document.validity.from.to_string(),
        "productIdentifiers": [{
            "scheme": scheme_uri(&subject.scheme),
            "value": untp_identifier_value(subject),
        }],
        "passportIssuer": {"id": document.eo_id, "name": document.eo_id},
        "standardsConformance": p
            .profiles
            .iter()
            .map(|profile| json!({
                "standard": profile.id,
                "conformanceVersion": profile.version,
                "effectiveFrom": profile
                    .effective_from
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| document.created_at.to_string()),
            }))
            .collect::<Vec<_>>(),
    });
    if let Some(valid_until) = document.validity.to {
        passport_vc["validUntil"] = json!(valid_until.to_string());
    }

    // Conformity claims: one credential per profile binding (the
    // profile IS the conformity claim — "their format is our profile")
    // plus one per E14 inspection stamp in the log.
    let mut conformity: Vec<Value> = p
        .profiles
        .iter()
        .map(|profile| {
            json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://ref.gs1.org/gs1/voc/"
                ],
                "type": ["VerifiableCredential", "DigitalConformityCredential"],
                "id": format!(
                    "{}#conformity-profile-{}",
                    document.passport_id.as_str(),
                    slug_tail(&profile.id)
                ),
                "issuer": {"id": document.eo_id, "name": document.eo_id},
                "validFrom": document.validity.from.to_string(),
                "credentialSubject": {
                    "type": "ConformityAttestation",
                    "assessmentLevel": "self-assessment",
                    "conformity": {
                        "standard": profile.id,
                        "version": profile.version,
                    },
                    "criteria": "profile binding on the neutral core",
                },
            })
        })
        .collect();
    for sealed in document.log.sealed() {
        let EventPayload::InspectionStamp { stamp } = &sealed.event.payload else {
            continue;
        };
        let assessment_level = if sealed.event.trust >= unidpp_model::TrustMarker::Attested {
            "third-party"
        } else {
            "self-assessment"
        };
        conformity.push(json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://ref.gs1.org/gs1/voc/"
            ],
            "type": ["VerifiableCredential", "DigitalConformityCredential"],
            "id": format!("{}#conformity-stamp-{}", document.passport_id.as_str(), sealed.event.seq),
            "issuer": {"id": stamp.attester, "name": stamp.attester},
            "validFrom": sealed.event.occurred_at.to_string(),
            "credentialSubject": {
                "type": "ConformityAttestation",
                "assessmentLevel": assessment_level,
                "conformity": {
                    "standard": stamp.lens.as_str(),
                    "version": stamp.lens_version,
                },
                "criteria": stamp
                    .verdict_summary
                    .clone()
                    .unwrap_or_else(|| "inspection stamp".to_string()),
                "mode": stamp.mode.as_str(),
                "stateCommitment": stamp.subject_state_commitment.hex(),
                "logAnchoredAt": stamp.log_anchored_at.to_string(),
            },
        }));
    }

    // Link-resolver entry (DLR shape): the passport's Tier-B serving
    // pointer plus the offline chain anchor.
    let link = json!({
        "linkType": "untp-dpp",
        "target": document.resolver_uri,
        "relationship": "document",
        "id": document.passport_id.as_str(),
        "anchor": {
            "logHead": document.log.head().map(|h| h.hex()),
            "height": document.log.len(),
        },
    });

    // The verdict: the verify.py rule ladder over this evidence.
    let options = VerifyOptions {
        anchors: p.anchors.clone(),
        required_freshness,
        now,
        ..VerifyOptions::default()
    };
    let verdict = verdict::verify_passport(document, &options);

    json!({
        "rendering": {
            "profile": UNTP_PROFILE,
            "binding": "UNTP v0.x passport stub shape (unidpp-py/unidpp/adapters/untp.py)",
            "source": p.origin.as_str(),
            "as_of": now.to_string(),
        },
        "passport": passport_vc,
        "conformity": conformity,
        "link": link,
        "verdict": verdict.to_dict(),
    })
}

// ---------------------------------------------------------------------------
// The import direction (the py parse_untp_stub port)
// ---------------------------------------------------------------------------

/// Parse a UNTP-style passport stub into the neutral-core manifest
/// shape — the port of py `parse_untp_stub` (returns the py
/// `PassportManifest.to_dict` wire shape). The manifest's
/// `eventLog.commitment` is the canonical commitment over the stub
/// itself (an import receipt); the log URI is the stub's `id`.
pub fn parse_stub(stub: &Value, as_of: &str) -> Result<Value, String> {
    let Some(object) = stub.as_object() else {
        return Err("stub must be a JSON object".to_string());
    };
    let ptype = stub_type_string(stub).unwrap_or_else(|| "ProductPassport".to_string());
    if !ptype.to_lowercase().contains("passport") {
        return Err(format!("not a passport stub: type={ptype:?}"));
    }
    let ids = object
        .get("productIdentifiers")
        .and_then(Value::as_array)
        .ok_or_else(|| "stub has no productIdentifiers".to_string())?;
    let raw = ids
        .first()
        .and_then(Value::as_object)
        .ok_or_else(|| "stub has no productIdentifiers".to_string())?;
    let value = raw
        .get("value")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "identifier carries no value".to_string())?
        .to_string();
    let scheme = scheme_token(
        raw.get("scheme")
            .and_then(Value::as_str)
            .unwrap_or("https://gs1.org/voc/"),
    );
    let display = core_identifier_value(&scheme, &value);
    let subject = ProductIdentifier::parse(&display).map_err(|e| e.to_string())?;
    let granularity = granularity_token(subject.granularity);

    let stub_id = stub
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("urn:unidpp:import:{}", subject));
    let issuer = object.get("passportIssuer").cloned().unwrap_or(json!({}));
    if !issuer.is_object() {
        return Err("passportIssuer must be an object".to_string());
    }

    let valid_from = object
        .get("validFrom")
        .and_then(Value::as_str)
        .unwrap_or(as_of);
    let mut profiles: Vec<Value> = Vec::new();
    for conf in object
        .get("standardsConformance")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(conf) = conf.as_object() else {
            continue;
        };
        let version = conf
            .get("conformanceVersion")
            .or_else(|| conf.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("0");
        profiles.push(json!({
            "profileId": conf.get("standard").and_then(Value::as_str)
                .unwrap_or("urn:unidpp:profile:untp"),
            "version": version,
            "effective": {"from": valid_from},
        }));
    }

    Ok(json!({
        "passportId": {
            "scheme": scheme,
            // The py mint rule: a fresh 15459 passport URN over the
            // slug of the stub's identifier value (an import mint, not
            // the original passport id — that one rides the stub `id`).
            "value": format!(
                "urn:iso:std:iso-iec:15459:unidpp:passport:{}",
                slug(&value)
            ),
            "granularity": granularity,
            "state": "live",
        },
        "subjectId": {
            "scheme": scheme,
            "value": subject.to_string(),
            "granularity": granularity,
            "state": "live",
        },
        "status": "active",
        "profiles": profiles,
        "children": [],
        "eventLog": {
            "logUri": stub_id,
            "commitment": commitment(stub, "untp-import"),
            "height": 0,
        },
        "capabilityClass": "S0",
        "asOf": as_of,
    }))
}

/// The tail of a URN after the last `:` — credential-id safe.
fn slug_tail(id: &str) -> &str {
    id.rsplit(':').next().unwrap_or(id)
}

/// The `type` member as a string (the stub carries a VC type array; the
/// py stub shape carries a bare string — both accepted).
fn stub_type_string(stub: &Value) -> Option<String> {
    match stub.get("type") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    }
}

/// Granularity token — the py stub parser records identity at `item`
/// granularity unconditionally; the Rust port records the granularity
/// the identifier itself carries (I3), which is the core's doctrine.
fn granularity_token(granularity: Granularity) -> &'static str {
    granularity.as_str()
}

/// The py `_slug`: lowercase alphanumerics plus `:-_.`, everything
/// else dropped.
fn slug(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_alphanumeric() {
            out.extend(ch.to_lowercase());
        } else if matches!(ch, ':' | '-' | '_' | '.') {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ProfileRef;

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    fn tyre() -> GatewayPassport {
        let (document, profiles) = crate::fixtures::tyre();
        GatewayPassport::fixture(document, profiles)
    }

    fn laptop() -> GatewayPassport {
        let (document, profiles) = crate::fixtures::laptop();
        GatewayPassport::fixture(document, profiles)
    }

    #[test]
    fn scheme_mapping_round_trips_both_directions() {
        assert_eq!(scheme_uri(&IdScheme::Cpid), "https://unidpp.org/id/");
        assert_eq!(scheme_uri(&IdScheme::Gtin), "https://gs1.org/voc/");
        assert_eq!(scheme_token("https://unidpp.org/id/"), "cpid");
        assert_eq!(scheme_token("https://gs1.org/voc/"), "gtin");
        assert_eq!(
            scheme_token("https://example.org/other"),
            "https://example.org/other"
        );
    }

    #[test]
    fn gs1_values_use_parenthesized_application_identifiers() {
        let id = ProductIdentifier::parse("01+4006381333931+10+LOT9").unwrap();
        assert_eq!(untp_identifier_value(&id), "(01)4006381333931(10)LOT9");
        let back = core_identifier_value("gtin", "(01)4006381333931(10)LOT9");
        assert_eq!(back, "01+4006381333931+10+LOT9");
        assert_eq!(ProductIdentifier::parse(&back).unwrap(), id);
    }

    #[test]
    fn triad_shape_carries_the_stub_fields_the_py_parser_reads() {
        let now = ts("2026-09-07T12:00:00Z");
        let triad = render_triad(&laptop(), now, None);
        assert_eq!(triad["rendering"]["profile"], UNTP_PROFILE);
        assert_eq!(triad["rendering"]["source"], "fixture");
        let passport = &triad["passport"];
        assert_eq!(
            passport["id"],
            "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345"
        );
        assert_eq!(
            passport["productIdentifiers"][0]["scheme"],
            "https://unidpp.org/id/"
        );
        assert_eq!(
            passport["productIdentifiers"][0]["value"],
            "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345"
        );
        assert_eq!(
            passport["passportIssuer"]["id"],
            "urn:unidpp:actor:oem-nordwave"
        );
        assert_eq!(passport["validFrom"], "2026-08-03T09:15:00Z");
        assert_eq!(passport["validUntil"], "2036-08-03T09:15:00Z");
        assert_eq!(
            passport["standardsConformance"].as_array().unwrap().len(),
            2
        );
        assert_eq!(
            triad["link"]["target"],
            "https://dpp.unidpp.org/r/84120099012345"
        );
        assert_eq!(triad["link"]["anchor"]["height"], 4);
        assert_eq!(triad["verdict"]["outcome"], "pass");
        // Laptop has no inspection stamps: conformity = profiles only.
        assert_eq!(triad["conformity"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn tyre_stamp_becomes_a_third_party_conformity_credential() {
        let now = ts("2026-09-07T12:00:00Z");
        let triad = render_triad(&tyre(), now, None);
        let conformity = triad["conformity"].as_array().unwrap();
        assert_eq!(conformity.len(), 2); // profile + stamp
        let stamp_credential = &conformity[1];
        assert_eq!(
            stamp_credential["credentialSubject"]["assessmentLevel"],
            "third-party"
        );
        assert_eq!(
            stamp_credential["credentialSubject"]["conformity"]["standard"],
            "urn:unidpp:profile:eu-tyre-label"
        );
        assert_eq!(
            stamp_credential["issuer"]["id"],
            "urn:unidpp:actor:verifier-tuv"
        );
    }

    #[test]
    fn render_then_parse_round_trips_through_the_adapter_semantics() {
        let now = ts("2026-09-07T12:00:00Z");
        for p in [laptop(), tyre()] {
            let triad = render_triad(&p, now, None);
            let manifest =
                parse_stub(&triad["passport"], "2026-09-07T12:00:00Z").expect("stub parses");
            // The subject identity round-trips to the core form.
            assert_eq!(
                manifest["subjectId"]["value"],
                p.document.product_id.to_string()
            );
            // The py mint rule: a 15459 passport URN over the slug of
            // the stub's identifier value.
            let raw_value = triad["passport"]["productIdentifiers"][0]["value"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(
                manifest["passportId"]["value"],
                format!(
                    "urn:iso:std:iso-iec:15459:unidpp:passport:{}",
                    slug(&raw_value)
                )
            );
            assert_eq!(manifest["passportId"]["state"], "live");
            assert_eq!(manifest["status"], "active");
            // The original passport id rides the stub `id` (log URI).
            assert_eq!(
                manifest["eventLog"]["logUri"],
                p.document.passport_id.as_str()
            );
            let profiles = manifest["profiles"].as_array().unwrap();
            assert_eq!(profiles.len(), p.profiles.len());
            for (got, want) in profiles.iter().zip(p.profiles.iter()) {
                assert_eq!(got["profileId"], want.id);
                assert_eq!(got["version"], want.version);
            }
            // The import receipt: the commitment over the rendered stub.
            assert_eq!(
                manifest["eventLog"]["commitment"],
                commitment(&triad["passport"], "untp-import")
            );
        }
    }

    #[test]
    fn py_mint_rule_examples() {
        // The py docstring example shape: value "(01)0950..." slugs to
        // the bare digit run (parentheses are not slug characters).
        assert_eq!(slug("(01)09506000109347"), "0109506000109347");
        // The laptop subject is already slug-clean.
        let subject = "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345";
        assert_eq!(slug(subject), subject);
    }

    #[test]
    fn parser_rejects_non_passports_and_missing_identifiers() {
        assert!(parse_stub(&json!({"type": "Thing"}), "now").is_err());
        assert!(parse_stub(&json!({"type": "ProductPassport"}), "now").is_err());
        assert!(parse_stub(&json!({"type": "ProductPassport", "productIdentifiers": [{"scheme": "https://gs1.org/voc/", "value": ""}]}), "now").is_err());
        assert!(parse_stub(&json!({"type": "ProductPassport", "productIdentifiers": [{"scheme": "https://gs1.org/voc/", "value": "(01)4006381333931"}], "passportIssuer": "nope"}), "now").is_err());
        assert!(parse_stub(&json!({"type": "ProductPassport", "productIdentifiers": [{"scheme": "https://gs1.org/voc/", "value": "(01)4006381333931"}], "passportIssuer": {}}), "now").is_ok());
    }

    #[test]
    fn slug_matches_the_py_normalization() {
        assert_eq!(slug("urn:x-Y_Z.9"), "urn:x-y_z.9");
        assert_eq!(slug("///"), "unknown");
    }

    #[test]
    fn freshness_requirement_reaches_the_verdict() {
        let now = ts("2026-09-07T12:00:00Z");
        let triad = render_triad(&tyre(), now, Some("PT1H"));
        // Tyre evidence is 2026-06-12: stale under a 1-hour budget.
        assert_eq!(triad["verdict"]["freshness"], "stale");
        assert_eq!(triad["verdict"]["outcome"], "degraded");
    }

    #[test]
    fn profile_ref_wire_shape() {
        let profile = ProfileRef {
            id: "urn:p".into(),
            version: "2".into(),
            effective_from: Some(ts("2026-01-01T00:00:00Z")),
        };
        assert_eq!(profile.id, "urn:p");
    }
}
