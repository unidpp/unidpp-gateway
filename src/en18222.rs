//! The EN 18222 binding: the REST render —
//! `GET /v1/dppsByProductId/{gtin}?representation=full|compressed`.
//!
//! A compatibility render of OUR core in the EN's JSON shape: the wire
//! field set is mirrored exactly from the freeDPP live-endpoint
//! artifacts captured 2026-09-07 in
//! `unidpp-py/conformance/competitors/freedpp/artifacts/insulation-api-full.json`
//! and `insulation-api-compressed.json` (the reference C# models:
//! `FreeDppDppFull.cs` / `FreeDppDppCompressed.cs`). Per the EN, the
//! compressed serialization (EN 18223 clause 5.2) is the API default —
//! the C# model's own note: "compressed serialisation ... is default
//! according EN 18222".
//!
//! Wire shape (both representations share the header):
//!
//! | field | source in the neutral core |
//! |---|---|
//! | `digitalProductPassportId` | the passport URN (location-free, I14) |
//! | `uniqueProductIdentifier` | the GS1 key the route addressed |
//! | `granularity` | core granularity, capitalized (`Model`/`Batch`/`Item`) |
//! | `dppSchemaVersion` | `"0.1"` (the freeDPP/EN default) |
//! | `dppStatus` | replayed status (`issued` renders as `active`) |
//! | `lastUpdated` | last event time (full: seconds; compressed: `.0000000` fraction — the .NET `ToString("o")` behavior the artifacts print) |
//! | `economicOperatorId` / `facilityId` | the economic operator |
//! | `contentSpecificationIds` | `EN 18223:2026` + the bound profiles (`id@version`) |
//!
//! The full form carries `elements`: an array of `DataElementCollection`s
//! of `SingleValuedDataElement`s, every value printed as a string
//! (exactly as the artifacts print even booleans and floats). The
//! compressed form drops `elements` and keys the collections directly,
//! each leaf an object member with a **native** JSON value (`true`, not
//! `"true"`) — the serialization asymmetry the conformance register
//! documents (§ "Serialization asymmetry").
//!
//! Dictionary references are minted under `https://unidpp.org/dp/` —
//! the same role freeDPP's `https://insulation.freedpp.eu/property/`
//! URIs play for its element dictionary.

use serde_json::{json, Map, Value};
use unidpp_event::{EventPayload, Status};
use unidpp_model::{Granularity, IdScheme, Timestamp};

use crate::source::GatewayPassport;

/// The registered render profile.
pub const EN18222_PROFILE: &str = "urn:unidpp:profile:render:en18222";

/// The serialization the EN 18222 API serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Representation {
    Full,
    Compressed,
}

impl Representation {
    /// Parse the `?representation=` parameter. `None`/empty selects
    /// the EN default (compressed); anything else is a client error.
    pub fn parse(param: Option<&str>) -> Result<Representation, String> {
        match param.map(str::trim).filter(|s| !s.is_empty()) {
            None => Ok(Representation::Compressed),
            Some("full") => Ok(Representation::Full),
            Some("compressed") => Ok(Representation::Compressed),
            Some(other) => Err(format!(
                "unknown representation `{other}` (expected full|compressed)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Representation::Full => "full",
            Representation::Compressed => "compressed",
        }
    }
}

/// A typed leaf value: the compressed serialization's native typing.
enum Leaf {
    Str(String),
    Bool(bool),
    Num(i64),
}

/// One leaf data element (typed value; the wire typing happens per
/// representation in [`full_leaf`] / [`compressed_value`]).
struct LeafSpec {
    element_id: String,
    value: Leaf,
    xsd: &'static str,
}

/// Render the passport in the requested EN 18222 representation.
pub fn render(p: &GatewayPassport, representation: Representation, now: Timestamp) -> Value {
    let document = &p.document;
    let subject = &document.product_id;
    let last_updated = document.log.last_event_at().unwrap_or(document.created_at);

    let mut root = Map::new();
    root.insert(
        "digitalProductPassportId".into(),
        json!(document.passport_id.as_str()),
    );
    root.insert(
        "uniqueProductIdentifier".into(),
        json!(match subject.scheme {
            IdScheme::Gtin | IdScheme::Sgtin => subject.key.clone(),
            _ => subject.to_string(),
        }),
    );
    root.insert(
        "granularity".into(),
        json!(granularity_token(subject.granularity)),
    );
    root.insert("dppSchemaVersion".into(), json!("0.1"));
    root.insert(
        "dppStatus".into(),
        json!(status_token(document.log.current_status())),
    );
    root.insert(
        "lastUpdated".into(),
        json!(match representation {
            // Full prints to the second; compressed prints the .NET
            // round-trip "o" form with a 7-digit fraction.
            Representation::Full => last_updated.to_string().trim_end_matches('Z').to_string(),
            Representation::Compressed =>
                format!("{}.0000000", last_updated.to_string().trim_end_matches('Z')),
        }),
    );
    root.insert("economicOperatorId".into(), json!(document.eo_id));
    root.insert("facilityId".into(), json!(document.eo_id));
    let mut specs = vec!["EN 18223:2026".to_string()];
    specs.extend(
        p.profiles
            .iter()
            .map(|profile| format!("{}@{}", profile.id, profile.version)),
    );
    root.insert("contentSpecificationIds".into(), json!(specs));

    match representation {
        Representation::Full => {
            root.insert(
                "elements".into(),
                json!(collections(p)
                    .into_iter()
                    .map(|(element_id, leaves)| {
                        json!({
                            "elementId": element_id,
                            "objectType": "DataElementCollection",
                            "dictionaryReference": format!("https://unidpp.org/dp/{element_id}"),
                            "elements": leaves.iter().map(full_leaf).collect::<Vec<_>>(),
                        })
                    })
                    .collect::<Vec<_>>()),
            );
        }
        Representation::Compressed => {
            for (element_id, leaves) in collections(p) {
                let mut flat = Map::new();
                for leaf in &leaves {
                    flat.insert(leaf.element_id.clone(), compressed_value(leaf));
                }
                root.insert(element_id.to_string(), Value::Object(flat));
            }
        }
    }
    let _ = now; // the stamp rides the x-as-of header, not the frozen EN body
    Value::Object(root)
}

/// The element-tree collections: `(collection elementId, leaves)`.
fn collections(p: &GatewayPassport) -> Vec<(&'static str, Vec<LeafSpec>)> {
    let document = &p.document;
    let subject = &document.product_id;

    fn leaf(element_id: &str, value: Leaf, xsd: &'static str) -> LeafSpec {
        LeafSpec {
            element_id: element_id.to_string(),
            value,
            xsd,
        }
    }

    // c0 ProductInformation — identity and serving pointers.
    let mut c0 = vec![
        leaf(
            "_p_d_UniqueProductIdentifier",
            Leaf::Str(subject.to_string()),
            "xsd:string",
        ),
        leaf(
            "_p_d_PassportId",
            Leaf::Str(document.passport_id.as_str().into()),
            "xsd:anyURI",
        ),
    ];
    if matches!(subject.scheme, IdScheme::Gtin | IdScheme::Sgtin) {
        c0.insert(
            0,
            leaf("_p_d_GTIN", Leaf::Str(subject.key.clone()), "xsd:string"),
        );
    }
    if let Some(type_ref) = &document.type_ref {
        c0.push(leaf(
            "_p_d_TypeRef",
            Leaf::Str(type_ref.clone()),
            "xsd:string",
        ));
    }
    c0.push(leaf(
        "_p_d_CapabilityClass",
        Leaf::Str(document.capability.code().to_string()),
        "xsd:string",
    ));
    c0.push(leaf(
        "_p_d_ResolverUri",
        Leaf::Str(document.resolver_uri.clone()),
        "xsd:anyURI",
    ));

    // ca StateSafety — the replayed governance state.
    let ca = vec![
        leaf(
            "_p_d_DppStatus",
            Leaf::Str(status_token(document.log.current_status())),
            "xsd:string",
        ),
        leaf(
            "_p_d_RecallActive",
            Leaf::Bool(document.log.safety_flag() != unidpp_event::SafetyFlag::None),
            "xsd:boolean",
        ),
        leaf(
            "_p_d_LogHead",
            Leaf::Str(document.log.head().map(|h| h.hex()).unwrap_or_default()),
            "xsd:string",
        ),
        leaf(
            "_p_d_LogHeight",
            Leaf::Num(document.log.len() as i64),
            "xsd:integer",
        ),
        leaf(
            "_p_d_TrustMarker",
            Leaf::Str(strongest_marker(p)),
            "xsd:string",
        ),
    ];

    // cb ConformityEvidence — profile bindings + inspection stamps.
    let mut cb: Vec<LeafSpec> = p
        .profiles
        .iter()
        .map(|profile| {
            leaf(
                &format!("_p_d_Profile_{}", slug_tail(&profile.id)),
                Leaf::Str(format!("{}@{}", profile.id, profile.version)),
                "xsd:string",
            )
        })
        .collect();
    for sealed in document.log.sealed() {
        if let EventPayload::InspectionStamp { stamp } = &sealed.event.payload {
            cb.push(leaf(
                &format!("_p_d_Stamp_{}", sealed.event.seq),
                Leaf::Str(format!(
                    "{}|{}@{}|{}|{}",
                    stamp.attester,
                    stamp.lens.as_str(),
                    stamp.lens_version,
                    stamp.mode.as_str(),
                    stamp
                        .verdict_summary
                        .clone()
                        .unwrap_or_else(|| "inspection stamp".into())
                )),
                "xsd:string",
            ));
        }
    }
    if cb.is_empty() {
        cb.push(leaf(
            "_p_d_NoClaims",
            Leaf::Str("no profile bound".into()),
            "xsd:string",
        ));
    }

    // cw Documents — the render cross-links.
    let cw = vec![
        leaf(
            "_p_d_LinkResolverUri",
            Leaf::Str(document.resolver_uri.clone()),
            "xsd:anyURI",
        ),
        leaf(
            "_p_d_UntpRender",
            Leaf::Str(format!("/untp/product/{}", document.passport_id.as_str())),
            "xsd:anyURI",
        ),
    ];

    vec![
        ("c0ProductInformation", c0),
        ("caStateSafety", ca),
        ("cbConformityEvidence", cb),
        ("cwDocuments", cw),
    ]
}

/// The full serialization's wire leaf: every value printed as a string
/// — booleans included (`"true"`), exactly as the artifacts print.
fn full_leaf(spec: &LeafSpec) -> Value {
    let wire_value = match &spec.value {
        Leaf::Str(s) => s.clone(),
        Leaf::Bool(b) => b.to_string(),
        Leaf::Num(n) => n.to_string(),
    };
    json!({
        "elementId": &spec.element_id,
        "objectType": "SingleValuedDataElement",
        "dictionaryReference": format!("https://unidpp.org/dp/{}", spec.element_id),
        "valueDataType": spec.xsd,
        "value": wire_value,
    })
}

/// The compressed serialization's native value for a leaf.
fn compressed_value(spec: &LeafSpec) -> Value {
    match &spec.value {
        Leaf::Str(s) => json!(s),
        Leaf::Bool(b) => json!(b),
        Leaf::Num(n) => json!(n),
    }
}

fn granularity_token(granularity: Granularity) -> &'static str {
    match granularity {
        Granularity::Model => "Model",
        Granularity::Batch => "Batch",
        Granularity::Item => "Item",
    }
}

fn status_token(status: Status) -> String {
    match status {
        Status::Issued => "active".to_string(),
        other => other.as_str().to_string(),
    }
}

/// The strongest trust marker in the log (core token vocabulary).
fn strongest_marker(p: &GatewayPassport) -> String {
    p.document
        .log
        .sealed()
        .iter()
        .map(|s| s.event.trust)
        .max()
        .unwrap_or(unidpp_model::TrustMarker::Unsigned)
        .as_str()
        .to_string()
}

/// The tail of a URN after the last `:` — element-id safe.
fn slug_tail(id: &str) -> String {
    id.rsplit(':').next().unwrap_or(id).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::untp::UNTP_PROFILE;

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

    const FULL_KEYS: &[&str] = &[
        "digitalProductPassportId",
        "uniqueProductIdentifier",
        "granularity",
        "dppSchemaVersion",
        "dppStatus",
        "lastUpdated",
        "economicOperatorId",
        "facilityId",
        "contentSpecificationIds",
        "elements",
    ];

    /// The compressed artifact's top-level keys: the same header, minus
    /// `elements`, plus the collection keys (which the artifact names
    /// `c0ProductInformation`, `caDurabilityReliability`, … — ours are
    /// the collection ids we render).
    fn compressed_keys(rendered: &Value) -> Vec<String> {
        rendered
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| *k != "elements")
            .cloned()
            .collect()
    }

    #[test]
    fn representation_parameter_rules() {
        assert_eq!(
            Representation::parse(None).unwrap(),
            Representation::Compressed
        );
        assert_eq!(
            Representation::parse(Some("")).unwrap(),
            Representation::Compressed
        );
        assert_eq!(
            Representation::parse(Some("full")).unwrap(),
            Representation::Full
        );
        assert_eq!(
            Representation::parse(Some("compressed")).unwrap(),
            Representation::Compressed
        );
        assert!(Representation::parse(Some("json")).is_err());
    }

    #[test]
    fn full_render_matches_the_artifact_field_set() {
        let v = render(&tyre(), Representation::Full, ts("2026-09-07T12:00:00Z"));
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        assert_eq!(keys.len(), FULL_KEYS.len());
        for key in FULL_KEYS {
            assert!(v.get(*key).is_some(), "full render misses `{key}`");
        }
        // Header semantics.
        assert_eq!(v["dppSchemaVersion"], "0.1");
        assert_eq!(v["dppStatus"], "active");
        assert_eq!(v["granularity"], "Model");
        assert_eq!(v["uniqueProductIdentifier"], "4006381333931");
        assert_eq!(
            v["digitalProductPassportId"],
            "urn:unidpp:passport:tyre-4006381333931"
        );
        assert_eq!(v["economicOperatorId"], "urn:unidpp:actor:tyre-oem-conti");
        assert_eq!(v["facilityId"], v["economicOperatorId"]);
        // Full prints to the second, no fraction, no Z (artifact form).
        assert_eq!(v["lastUpdated"], "2026-06-12T16:31:00");
        assert_eq!(
            v["contentSpecificationIds"],
            json!(["EN 18223:2026", "urn:unidpp:profile:eu-tyre-label@1.0.0"])
        );
        // Element tree: collections of single-valued elements, every
        // value printed as a string.
        let elements = v["elements"].as_array().unwrap();
        assert!(elements.len() >= 4);
        for collection in elements {
            for key in ["elementId", "objectType", "dictionaryReference", "elements"] {
                assert!(collection.get(key).is_some());
            }
            assert_eq!(collection["objectType"], "DataElementCollection");
            for element in collection["elements"].as_array().unwrap() {
                let leaf_keys: Vec<&str> = element
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(|k| k.as_str())
                    .collect();
                assert_eq!(
                    leaf_keys,
                    vec![
                        "dictionaryReference",
                        "elementId",
                        "objectType",
                        "value",
                        "valueDataType"
                    ],
                    "the full-form leaf field set is frozen to the artifact's"
                );
                assert_eq!(element["objectType"], "SingleValuedDataElement");
                assert!(element["value"].is_string(), "full-form values are strings");
            }
        }
    }

    #[test]
    fn compressed_render_matches_the_artifact_field_set_and_types_natively() {
        let v = render(
            &tyre(),
            Representation::Compressed,
            ts("2026-09-07T12:00:00Z"),
        );
        assert!(
            v.get("elements").is_none(),
            "compressed drops the element tree"
        );
        let keys = compressed_keys(&v);
        assert_eq!(keys.len(), FULL_KEYS.len() - 1 + 4); // header minus elements + 4 collections
                                                         // The .NET "o" form the artifact prints (7-digit fraction).
        assert_eq!(v["lastUpdated"], "2026-06-12T16:31:00.0000000");
        // Native typing: booleans and integers, not strings.
        let state = &v["caStateSafety"];
        assert_eq!(state["_p_d_RecallActive"], json!(false));
        assert_eq!(state["_p_d_LogHeight"], json!(3));
        assert_eq!(state["_p_d_TrustMarker"], "attested");
        assert!(state["_p_d_LogHead"].is_string());
        // Conformity evidence carries the stamp.
        assert!(v["cbConformityEvidence"]["_p_d_Stamp_2"]
            .as_str()
            .unwrap()
            .contains("verifier-tuv"));
    }

    #[test]
    fn full_and_compressed_agree_on_every_leaf() {
        let full = render(&laptop(), Representation::Full, ts("2026-09-07T12:00:00Z"));
        let compressed = render(
            &laptop(),
            Representation::Compressed,
            ts("2026-09-07T12:00:00Z"),
        );
        for collection in full["elements"].as_array().unwrap() {
            let id = collection["elementId"].as_str().unwrap();
            let flat = compressed
                .get(id)
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("compressed misses collection {id}"));
            for element in collection["elements"].as_array().unwrap() {
                let leaf_id = element["elementId"].as_str().unwrap();
                let native = &flat[leaf_id];
                // The string print and the native value agree.
                match native {
                    Value::Bool(b) => assert_eq!(element["value"], b.to_string()),
                    Value::Number(n) => assert_eq!(element["value"], n.to_string()),
                    Value::String(s) => assert_eq!(element["value"], *s),
                    other => panic!("unexpected native value {other:?}"),
                }
            }
            assert_eq!(flat.len(), collection["elements"].as_array().unwrap().len());
        }
    }

    #[test]
    fn laptop_renders_its_two_profiles_and_no_stamps() {
        let v = render(
            &laptop(),
            Representation::Compressed,
            ts("2026-09-07T12:00:00Z"),
        );
        let cb = &v["cbConformityEvidence"];
        assert_eq!(
            cb["_p_d_Profile_eu-espr-electronics"],
            "urn:unidpp:profile:eu-espr-electronics@1.3.0"
        );
        assert_eq!(
            cb["_p_d_Profile_jp-meti-pse"],
            "urn:unidpp:profile:jp-meti-pse@2026.2"
        );
        assert!(v["caStateSafety"]["_p_d_LogHeight"] == json!(4));
        assert!(v["caStateSafety"]["_p_d_RecallActive"] == json!(false));
    }

    #[test]
    fn render_is_pure_over_the_stamp_instant() {
        let a = render(&tyre(), Representation::Full, ts("2026-01-01T00:00:00Z"));
        let b = render(&tyre(), Representation::Full, ts("2030-01-01T00:00:00Z"));
        assert_eq!(
            a, b,
            "the EN body is frozen; the as-of stamp rides the header"
        );
    }

    #[test]
    fn profiles_render_distinctly_from_the_untp_profile() {
        assert_ne!(EN18222_PROFILE, UNTP_PROFILE);
        assert_eq!(EN18222_PROFILE, "urn:unidpp:profile:render:en18222");
    }
}
