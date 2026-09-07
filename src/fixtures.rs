//! The seeded fixture passports — the fallback data source when no
//! issuer is configured (mirroring the `unidpp-gate` doctrine:
//! upstream-when-reachable, seeded fixtures otherwise).
//!
//! Both passports are minted with the CLI's own machinery
//! (`unidpp_cli::passport::Passport::mint` — what `unidpp create`
//! runs) and extended with typed events (what `unidpp event` runs), so
//! the fixtures are exactly the documents a `unidpp-cli` deployment
//! produces:
//!
//! - **laptop** — the stream-11 pilot fixture (ported from
//!   `unidpp-ts/packages/model/src/fixtures/laptop.ts` /
//!   `unidpp-core` demo scenario `laptop`): one neutral core under two
//!   jurisdiction lenses (EU ESPR electronics + JP METI PSE), custody
//!   transfer, firmware update, part replacement.
//! - **tyre (E8)** — the consumable loop: a GTIN-identified tyre
//!   passport with an E8 `consumable.replace` event (the recurring
//!   tyres/filters class) and an E14 `inspection.stamp` attestation,
//!   giving both renders real conformity evidence. The GTIN identity
//!   is what the EN 18222 `dppsByProductId` route keys on.
//!
//! Event timestamps are fixed (deterministic renders); `created_at`
//! and the derived validity default are pinned through explicit
//! `valid_from`/`valid_to`.

use unidpp_cli::passport::{MintOptions, Passport};
use unidpp_event::{EventPayload, EventType, Stamp, StampMode, TypedEvent};
use unidpp_model::{PassportId, ProfileId, Timestamp, TrustMarker};

use crate::source::ProfileRef;

fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("fixture timestamps are fixed and parse")
}

fn pid(s: &str) -> PassportId {
    PassportId::new(s).expect("fixture passport ids are well-formed")
}

/// Append one typed event to a document's log (the CLI `event` path).
fn append(doc: &mut Passport, event: TypedEvent) {
    doc.log
        .append(event, None, None)
        .expect("fixture event appends");
}

/// The laptop fixture: EU + JP lenses on one neutral core.
pub fn laptop() -> (Passport, Vec<ProfileRef>) {
    let mut doc = Passport::mint(MintOptions {
        id: "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345".into(),
        granularity: None,
        type_ref: Some("urn:iso:std:iso-iec:15459:unidpp:type:lat-7@hw-rev-b".into()),
        capability: "S0".into(),
        eo_id: Some("urn:unidpp:actor:oem-nordwave".into()),
        resolver_uri: Some("https://dpp.unidpp.org/r/84120099012345".into()),
        passport_id: Some("urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345".into()),
        valid_from: Some(ts("2026-08-03T09:15:00Z")),
        valid_to: Some(ts("2036-08-03T09:15:00Z")),
    })
    .expect("laptop fixture mints");

    append(
        &mut doc,
        TypedEvent::new(
            0,
            ts("2026-08-03T09:15:00Z"),
            "issuing authority",
            "urn:unidpp:actor:oem-nordwave",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::Attested,
        )
        .expect("issuance event builds"),
    );
    append(
        &mut doc,
        TypedEvent::new(
            1,
            ts("2026-08-20T14:02:00Z"),
            "custodian",
            "urn:unidpp:actor:retailer-kyoto-denshi",
            EventType::CustodyTransfer,
            EventPayload::CustodyTransfer {
                from: "urn:unidpp:actor:oem-nordwave".into(),
                to: "urn:unidpp:actor:consumer-anon-1".into(),
                counterparty_signed: true,
            },
            TrustMarker::SelfDeclared,
        )
        .expect("custody event builds"),
    );
    append(
        &mut doc,
        TypedEvent::new(
            2,
            ts("2026-11-05T02:30:00Z"),
            "economic operator",
            "urn:unidpp:actor:oem-nordwave",
            EventType::SoftwareUpdate,
            EventPayload::SoftwareUpdate {
                versions: [("system-firmware".to_string(), "1.07".to_string())]
                    .into_iter()
                    .collect(),
                unlocked_features: vec![],
            },
            TrustMarker::SelfDeclared,
        )
        .expect("firmware event builds"),
    );
    append(
        &mut doc,
        TypedEvent::new(
            3,
            ts("2027-02-11T10:44:00Z"),
            "repairer",
            "urn:unidpp:actor:repair-shibuya",
            EventType::PartReplace,
            EventPayload::PartReplace {
                removed: pid("urn:unidpp:passport:sodimm-16g-aa117-0042"),
                added: pid("urn:unidpp:passport:sodimm-32g-aa119-0007"),
                like_for_like: false,
            },
            TrustMarker::Attested,
        )
        .expect("part-replace event builds"),
    );

    let profiles = vec![
        ProfileRef {
            id: "urn:unidpp:profile:eu-espr-electronics".into(),
            version: "1.3.0".into(),
            effective_from: Some(ts("2027-01-01T00:00:00Z")),
        },
        ProfileRef {
            id: "urn:unidpp:profile:jp-meti-pse".into(),
            version: "2026.2".into(),
            effective_from: Some(ts("2026-10-01T00:00:00Z")),
        },
    ];
    (doc, profiles)
}

/// The tyre fixture: the E8 consumable loop plus an E14 inspection
/// stamp (conformity evidence for both renders).
pub fn tyre() -> (Passport, Vec<ProfileRef>) {
    let passport_id = "urn:unidpp:passport:tyre-4006381333931";
    let mut doc = Passport::mint(MintOptions {
        id: "gtin:4006381333931".into(),
        granularity: None,
        type_ref: Some("tyre-205-55-r16".into()),
        capability: "S1".into(),
        eo_id: Some("urn:unidpp:actor:tyre-oem-conti".into()),
        resolver_uri: Some("https://dpp.unidpp.org/r/4006381333931".into()),
        passport_id: Some(passport_id.into()),
        valid_from: Some(ts("2026-05-04T08:00:00Z")),
        valid_to: Some(ts("2036-05-04T08:00:00Z")),
    })
    .expect("tyre fixture mints");

    append(
        &mut doc,
        TypedEvent::new(
            0,
            ts("2026-05-04T08:00:00Z"),
            "issuing authority",
            "urn:unidpp:actor:tyre-oem-conti",
            EventType::Issuance,
            EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            TrustMarker::Attested,
        )
        .expect("issuance event builds"),
    );
    // E8 consumable.replace: the recurring tyres/filters class — the
    // worn tyre comes out, this passport's tyre goes in.
    append(
        &mut doc,
        TypedEvent::new(
            1,
            ts("2026-06-12T16:30:00Z"),
            "repairer",
            "urn:unidpp:actor:garage-muc-42",
            EventType::ConsumableReplace,
            EventPayload::ConsumableReplace {
                removed: pid("urn:unidpp:passport:tyre-worn-0091"),
                added: pid(passport_id),
            },
            TrustMarker::Attested,
        )
        .expect("consumable-replace event builds"),
    );
    // E14 inspection.stamp: lens-scoped attestation by a verifier.
    append(
        &mut doc,
        TypedEvent::new(
            2,
            ts("2026-06-12T16:31:00Z"),
            "verifier",
            "urn:unidpp:actor:verifier-tuv",
            EventType::InspectionStamp,
            EventPayload::InspectionStamp {
                stamp: Stamp {
                    attester: "urn:unidpp:actor:verifier-tuv".into(),
                    subject: pid(passport_id),
                    subject_state_commitment: unidpp_model::sha256(&[b"fixture|tyre-state|0"]),
                    lens: ProfileId::new("urn:unidpp:profile:eu-tyre-label")
                        .expect("lens id is well-formed"),
                    lens_version: "1.0.0".into(),
                    mode: StampMode::Snapshot,
                    verdict_summary: Some(
                        "conformity: eu-tyre-label@1.0.0 — wear indicator present, \
                         DOT week 22/2026, rolling resistance class B"
                            .into(),
                    ),
                    coverage_report: None,
                    log_anchored_at: ts("2026-06-12T16:31:00Z"),
                    quantity_context: None,
                },
            },
            TrustMarker::Attested,
        )
        .expect("inspection stamp builds"),
    );

    let profiles = vec![ProfileRef {
        id: "urn:unidpp:profile:eu-tyre-label".into(),
        version: "1.0.0".into(),
        effective_from: Some(ts("2026-06-01T00:00:00Z")),
    }];
    (doc, profiles)
}

/// The full seeded fixture set, in stable order.
pub fn all() -> Vec<(Passport, Vec<ProfileRef>)> {
    vec![laptop(), tyre()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laptop_fixture_matches_the_pilot_identity() {
        let (doc, profiles) = laptop();
        assert_eq!(
            doc.passport_id.as_str(),
            "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345"
        );
        assert_eq!(
            doc.product_id.to_string(),
            "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345"
        );
        assert_eq!(doc.log.len(), 4);
        assert_eq!(doc.log.current_status().as_str(), "issued");
        assert_eq!(doc.log.safety_flag().as_str(), "none");
        assert!(doc.log.head().is_some());
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].id, "urn:unidpp:profile:eu-espr-electronics");
    }

    #[test]
    fn tyre_fixture_carries_the_e8_event_and_stamp() {
        let (doc, profiles) = tyre();
        assert_eq!(doc.product_id.key, "4006381333931");
        assert_eq!(doc.log.len(), 3);
        let types: Vec<&str> = doc
            .log
            .sealed()
            .iter()
            .map(|s| s.event.event_type.as_str())
            .collect();
        assert_eq!(
            types,
            vec!["issuance", "consumable.replace", "inspection.stamp"]
        );
        assert_eq!(doc.log.stamps().len(), 1);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].version, "1.0.0");
    }

    #[test]
    fn fixtures_are_deterministic_in_their_evidence() {
        let (a, _) = tyre();
        let (b, _) = tyre();
        assert_eq!(a.log, b.log);
        assert_eq!(a.passport_id, b.passport_id);
    }
}
