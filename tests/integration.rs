//! Integration tests: real HTTP against gateway servers spawned on
//! ephemeral ports, plus one scenario driving a real `unidpp-issuer`
//! instance (issuer-mode rendering with live anchor verification) —
//! the house pattern (no reqwest; the hand-rolled `http` client).
//!
//! Coverage: discovery/health; the UNTP verifiable-credential triad
//! validated against the py adapter's stub-shape expectations; the
//! verdict's freshness rule over HTTP; the EN 18222 render's field set
//! checked against the freeDPP artifact key sets (cited inline); the
//! full↔compressed and render→parse round-trips; the no-information
//! 404; and the issuer upstream (live + unreachable-fallback).

use std::time::Duration;

use serde_json::{json, Value};
use unidpp_gateway::http::{json_request, HttpResponse};
use unidpp_gateway::untp;
use unidpp_gateway::{Config, TestServer};

const TIMEOUT: Duration = Duration::from_secs(10);

async fn spawn_fixtures() -> TestServer {
    TestServer::spawn(Config::default())
        .await
        .expect("spawn gateway (fixtures)")
}

async fn spawn(issuer_url: Option<String>) -> TestServer {
    TestServer::spawn(Config {
        issuer_url,
        ..Config::default()
    })
    .await
    .expect("spawn gateway")
}

async fn get(base: &str, path: &str) -> HttpResponse {
    json_request("GET", &format!("{base}{path}"), None, None, TIMEOUT)
        .await
        .expect("http request")
}

fn json_of(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.body_string()).expect("response JSON")
}

async fn post_json(base: &str, path: &str, body: &Value) -> HttpResponse {
    json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        None,
        TIMEOUT,
    )
    .await
    .expect("http request")
}

const LAPTOP_PASSPORT_ID: &str = "urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345";
const LAPTOP_PRODUCT_ID: &str = "cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345";
const TYRE_GTIN: &str = "4006381333931";
const TYRE_PASSPORT_ID: &str = "urn:unidpp:passport:tyre-4006381333931";

/// The artifact's full-serialization top-level key set
/// (insulation-api-full.json, captured 2026-09-07).
const ARTIFACT_FULL_KEYS: &[&str] = &[
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

/// The artifact's full-serialization leaf key set.
const ARTIFACT_LEAF_KEYS: &[&str] = &[
    "elementId",
    "objectType",
    "dictionaryReference",
    "valueDataType",
    "value",
];

/// The artifact's full-serialization collection key set.
const ARTIFACT_COLLECTION_KEYS: &[&str] =
    &["elementId", "objectType", "dictionaryReference", "elements"];

// ---------------------------------------------------------------------------
// Discovery + health
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_documents_both_bindings_as_c4_renders() {
    let server = spawn_fixtures().await;
    let response = get(&server.base_url, "/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert!(response.header("x-as-of").is_some());
    let doc: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert_eq!(doc["service"], "unidpp-gateway");
    let bindings = doc["bindings"].as_object().unwrap();
    assert_eq!(bindings.len(), 2, "exactly the two protocol bindings");
    assert_eq!(
        doc["bindings"]["untp"]["profile"],
        "urn:unidpp:profile:render:untp"
    );
    assert_eq!(
        doc["bindings"]["en18222"]["profile"],
        "urn:unidpp:profile:render:en18222"
    );
    assert_eq!(
        doc["endpoints"]["untp"],
        "GET /untp/product/{id}?freshness="
    );
    assert_eq!(
        doc["endpoints"]["en18222"],
        "GET /en18222/v1/dppsByProductId/{gtin}?representation=full|compressed"
    );
    assert!(doc["c4"].as_str().unwrap().contains("C4"));
    // The fixture index names both seeded passports.
    let fixtures = doc["source"]["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 2);
    server.stop().await;
}

#[tokio::test]
async fn healthz_is_ok() {
    let server = spawn_fixtures().await;
    let response = get(&server.base_url, "/healthz").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body_string(), "ok");
    assert!(response.header("x-as-of").is_some());
    server.stop().await;
}

// ---------------------------------------------------------------------------
// UNTP render
// ---------------------------------------------------------------------------

#[tokio::test]
async fn untp_render_serves_the_vc_triad() {
    let server = spawn_fixtures().await;
    let response = get(
        &server.base_url,
        &format!("/untp/product/{}", urlenc(LAPTOP_PASSPORT_ID)),
    )
    .await;
    assert_eq!(response.status, 200);
    assert!(response.header("x-as-of").is_some());
    let triad: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert_eq!(triad["as_of"], response.header("x-as-of").unwrap());
    assert_eq!(triad["rendering"]["source"], "fixture");
    assert_eq!(
        triad["rendering"]["profile"],
        "urn:unidpp:profile:render:untp"
    );

    // The passport VC — the py stub shape the adapter parses.
    let passport = &triad["passport"];
    let contexts = passport["@context"].as_array().unwrap();
    assert!(contexts
        .iter()
        .any(|c| c == "https://www.w3.org/ns/credentials/v2"));
    let types = passport["type"].as_array().unwrap();
    assert!(types.iter().any(|t| t == "VerifiableCredential"));
    assert!(types.iter().any(|t| t == "DigitalProductPassport"));
    assert_eq!(passport["id"], LAPTOP_PASSPORT_ID);
    // The 15459-URN identifier mapping (py _SCHEME_MAP inverse).
    assert_eq!(
        passport["productIdentifiers"][0]["scheme"],
        "https://unidpp.org/id/"
    );
    assert_eq!(
        passport["productIdentifiers"][0]["value"],
        LAPTOP_PRODUCT_ID
    );
    assert_eq!(
        passport["passportIssuer"]["id"],
        "urn:unidpp:actor:oem-nordwave"
    );
    assert_eq!(passport["validFrom"], "2026-08-03T09:15:00Z");
    assert_eq!(passport["validUntil"], "2036-08-03T09:15:00Z");
    // Conformity claims: both jurisdiction lenses.
    let conformance = passport["standardsConformance"].as_array().unwrap();
    assert_eq!(conformance.len(), 2);
    assert!(conformance
        .iter()
        .any(|c| c["standard"] == "urn:unidpp:profile:eu-espr-electronics"));

    // The link resolver entry.
    assert_eq!(triad["link"]["linkType"], "untp-dpp");
    assert_eq!(
        triad["link"]["target"],
        "https://dpp.unidpp.org/r/84120099012345"
    );
    assert_eq!(triad["link"]["anchor"]["height"], 4);
    assert_eq!(
        triad["link"]["anchor"]["logHead"].as_str().unwrap().len(),
        64
    );

    // The verdict (verify.py rule ladder).
    assert_eq!(triad["verdict"]["outcome"], "pass");
    assert_eq!(triad["verdict"]["reading"], "current-state");
    assert_eq!(triad["verdict"]["freshness"], "unknown");
    assert_eq!(triad["verdict"]["achievedMarker"], "unsigned");
    assert_eq!(triad["verdict"]["coverage"]["checks"], 3);

    // Conformity credentials: one per profile (the laptop log has no
    // inspection stamps).
    assert_eq!(triad["conformity"].as_array().unwrap().len(), 2);
    assert_eq!(
        triad["conformity"][0]["type"][1],
        "DigitalConformityCredential"
    );
    server.stop().await;
}

#[tokio::test]
async fn untp_render_resolves_by_product_identity_and_gtin() {
    let server = spawn_fixtures().await;
    for id in [LAPTOP_PRODUCT_ID, TYRE_GTIN, TYRE_PASSPORT_ID] {
        let response = get(&server.base_url, &format!("/untp/product/{}", urlenc(id))).await;
        assert_eq!(response.status, 200, "resolve by {id}");
        let triad: Value = serde_json::from_str(&response.body_string()).unwrap();
        assert!(!triad["passport"]["id"].is_null());
    }
    // The tyre render carries its inspection-stamp conformity credential.
    let response = get(
        &server.base_url,
        &format!("/untp/product/{}", urlenc(TYRE_PASSPORT_ID)),
    )
    .await;
    let triad: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert_eq!(triad["conformity"].as_array().unwrap().len(), 2);
    assert_eq!(
        triad["conformity"][1]["credentialSubject"]["assessmentLevel"],
        "third-party"
    );
    assert_eq!(
        triad["conformity"][1]["issuer"]["id"],
        "urn:unidpp:actor:verifier-tuv"
    );
    server.stop().await;
}

#[tokio::test]
async fn untp_verdict_freshness_rule_over_http() {
    let server = spawn_fixtures().await;
    // Tyre evidence is 2026-06-12: stale under a 1-hour budget —
    // degrades explicitly, never silently passes (I13).
    let response = get(
        &server.base_url,
        &format!("/untp/product/{}?freshness=PT1H", urlenc(TYRE_PASSPORT_ID)),
    )
    .await;
    assert_eq!(response.status, 200);
    let triad: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert_eq!(triad["verdict"]["freshness"], "stale");
    assert_eq!(triad["verdict"]["outcome"], "degraded");
    // The laptop's last event (part replace) is 2027-02-11 —
    // future-dated evidence reads fresh under any budget.
    let response = get(
        &server.base_url,
        &format!(
            "/untp/product/{}?freshness=PT1H",
            urlenc(LAPTOP_PASSPORT_ID)
        ),
    )
    .await;
    let triad: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert_eq!(triad["verdict"]["freshness"], "fresh");
    assert_eq!(triad["verdict"]["outcome"], "pass");
    server.stop().await;
}

#[tokio::test]
async fn untp_bad_freshness_budget_is_rejected() {
    let server = spawn_fixtures().await;
    let response = get(
        &server.base_url,
        &format!("/untp/product/{}?freshness=soon", urlenc(TYRE_PASSPORT_ID)),
    )
    .await;
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert!(body["error"].as_str().unwrap().contains("ISO 8601"));
    server.stop().await;
}

#[tokio::test]
async fn untp_round_trip_through_the_py_adapter_semantics() {
    let server = spawn_fixtures().await;
    let response = get(
        &server.base_url,
        &format!("/untp/product/{}", urlenc(TYRE_PASSPORT_ID)),
    )
    .await;
    let triad: Value = serde_json::from_str(&response.body_string()).unwrap();
    // The gateway's own port of the py parse_untp_stub must re-ingest
    // the render: subject identity, profiles, log URI, import receipt.
    let manifest = untp::parse_stub(&triad["passport"], "2026-09-07T00:00:00Z")
        .expect("rendered stub parses like a UNTP stub");
    assert_eq!(manifest["subjectId"]["value"], format!("01+{TYRE_GTIN}"));
    assert_eq!(manifest["subjectId"]["scheme"], "gtin");
    assert_eq!(manifest["eventLog"]["logUri"], TYRE_PASSPORT_ID);
    let profiles = manifest["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0]["profileId"], "urn:unidpp:profile:eu-tyre-label");
    assert_eq!(profiles[0]["version"], "1.0.0");
    assert_eq!(
        manifest["eventLog"]["commitment"],
        unidpp_gateway::canonical::commitment(&triad["passport"], "untp-import")
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// EN 18222 render
// ---------------------------------------------------------------------------

#[tokio::test]
async fn en18222_full_field_set_matches_the_freedpp_artifact() {
    let server = spawn_fixtures().await;
    let response = get(
        &server.base_url,
        &format!(
            "/en18222/v1/dppsByProductId/{}?representation=full",
            TYRE_GTIN
        ),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert!(
        response.header("x-as-of").is_some(),
        "the stamp rides the header"
    );
    let v: Value = serde_json::from_str(&response.body_string()).unwrap();
    // The body carries no as_of member: the wire shape is frozen.
    assert!(v.get("as_of").is_none());

    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    let mut expected = ARTIFACT_FULL_KEYS.to_vec();
    expected.sort_unstable();
    // Field SET equality (JSON object order is not load-bearing; the
    // artifact prints .NET insertion order, this body prints sorted).
    assert_eq!(keys, expected, "top-level field set == artifact");

    assert_eq!(v["digitalProductPassportId"], TYRE_PASSPORT_ID);
    assert_eq!(v["uniqueProductIdentifier"], TYRE_GTIN);
    assert_eq!(v["granularity"], "Model");
    assert_eq!(v["dppSchemaVersion"], "0.1");
    assert_eq!(v["dppStatus"], "active");
    assert_eq!(v["lastUpdated"], "2026-06-12T16:31:00");
    assert_eq!(v["economicOperatorId"], "urn:unidpp:actor:tyre-oem-conti");
    assert_eq!(v["facilityId"], v["economicOperatorId"]);
    assert_eq!(
        v["contentSpecificationIds"],
        json!(["EN 18223:2026", "urn:unidpp:profile:eu-tyre-label@1.0.0"])
    );

    let elements = v["elements"].as_array().unwrap();
    assert!(elements.len() >= 4);
    for collection in elements {
        let mut collection_keys: Vec<&str> = collection
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        collection_keys.sort_unstable();
        let mut expected_collection = ARTIFACT_COLLECTION_KEYS.to_vec();
        expected_collection.sort_unstable();
        assert_eq!(collection_keys, expected_collection);
        assert_eq!(collection["objectType"], "DataElementCollection");
        assert!(collection["dictionaryReference"]
            .as_str()
            .unwrap()
            .starts_with("https://unidpp.org/dp/"));
        for element in collection["elements"].as_array().unwrap() {
            let mut leaf_keys: Vec<&str> = element
                .as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect();
            leaf_keys.sort_unstable();
            let mut expected_leaf = ARTIFACT_LEAF_KEYS.to_vec();
            expected_leaf.sort_unstable();
            assert_eq!(leaf_keys, expected_leaf);
            assert_eq!(element["objectType"], "SingleValuedDataElement");
            // The full serialization prints every value as a string.
            assert!(element["value"].is_string());
            assert!(element["valueDataType"]
                .as_str()
                .unwrap()
                .starts_with("xsd:"));
        }
    }
    server.stop().await;
}

#[tokio::test]
async fn en18222_compressed_field_set_matches_the_freedpp_artifact() {
    let server = spawn_fixtures().await;
    let response = get(
        &server.base_url,
        &format!(
            "/en18222/v1/dppsByProductId/{}?representation=compressed",
            TYRE_GTIN
        ),
    )
    .await;
    assert_eq!(response.status, 200);
    let v: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert!(
        v.get("elements").is_none(),
        "compressed drops the element tree"
    );
    let object = v.as_object().unwrap();
    // Header (9 keys, artifact compressed form) + the 4 collections.
    assert_eq!(object.len(), ARTIFACT_FULL_KEYS.len() - 1 + 4);
    // The .NET "o" timestamp the artifact prints.
    assert_eq!(v["lastUpdated"], "2026-06-12T16:31:00.0000000");
    // Native JSON typing (the serialization asymmetry).
    let state = &v["caStateSafety"];
    assert_eq!(state["_p_d_RecallActive"], json!(false));
    assert_eq!(state["_p_d_LogHeight"], json!(3));
    assert_eq!(state["_p_d_TrustMarker"], "attested");
    assert_eq!(state["_p_d_LogHead"].as_str().unwrap().len(), 64);
    // Identity + serving pointers.
    let info = &v["c0ProductInformation"];
    assert_eq!(info["_p_d_GTIN"], TYRE_GTIN);
    assert_eq!(
        info["_p_d_ResolverUri"],
        "https://dpp.unidpp.org/r/4006381333931"
    );
    // The stamp prints its attester in the conformity evidence.
    assert!(v["cbConformityEvidence"]["_p_d_Stamp_2"]
        .as_str()
        .unwrap()
        .contains("verifier-tuv"));
    server.stop().await;
}

#[tokio::test]
async fn en18222_defaults_to_compressed_per_the_en() {
    let server = spawn_fixtures().await;
    let defaulted = get(
        &server.base_url,
        &format!("/en18222/v1/dppsByProductId/{}", TYRE_GTIN),
    )
    .await;
    let explicit = get(
        &server.base_url,
        &format!(
            "/en18222/v1/dppsByProductId/{}?representation=compressed",
            TYRE_GTIN
        ),
    )
    .await;
    assert_eq!(defaulted.status, 200);
    assert_eq!(defaulted.body_string(), explicit.body_string());
    assert!(serde_json::from_str::<Value>(&defaulted.body_string())
        .unwrap()
        .get("elements")
        .is_none());
    server.stop().await;
}

#[tokio::test]
async fn en18222_rejects_unknown_representation() {
    let server = spawn_fixtures().await;
    let response = get(
        &server.base_url,
        &format!(
            "/en18222/v1/dppsByProductId/{}?representation=json",
            TYRE_GTIN
        ),
    )
    .await;
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert!(body["error"].as_str().unwrap().contains("full|compressed"));
    server.stop().await;
}

#[tokio::test]
async fn en18222_full_and_compressed_agree_on_every_leaf() {
    let server = spawn_fixtures().await;
    let full = get(
        &server.base_url,
        &format!(
            "/en18222/v1/dppsByProductId/{}?representation=full",
            TYRE_GTIN
        ),
    )
    .await;
    let compressed = get(
        &server.base_url,
        &format!(
            "/en18222/v1/dppsByProductId/{}?representation=compressed",
            TYRE_GTIN
        ),
    )
    .await;
    let full: Value = serde_json::from_str(&full.body_string()).unwrap();
    let compressed: Value = serde_json::from_str(&compressed.body_string()).unwrap();
    let mut leaves = 0usize;
    for collection in full["elements"].as_array().unwrap() {
        let id = collection["elementId"].as_str().unwrap();
        let flat = compressed
            .get(id)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("compressed misses collection {id}"));
        for element in collection["elements"].as_array().unwrap() {
            let leaf_id = element["elementId"].as_str().unwrap();
            leaves += 1;
            match &flat[leaf_id] {
                Value::Bool(b) => assert_eq!(element["value"], b.to_string()),
                Value::Number(n) => assert_eq!(element["value"], n.to_string()),
                Value::String(s) => assert_eq!(element["value"], *s),
                other => panic!("unexpected native value {other:?}"),
            }
        }
        assert_eq!(flat.len(), collection["elements"].as_array().unwrap().len());
    }
    assert!(
        leaves >= 15,
        "the render carries a real element set ({leaves} leaves)"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// No-information 404s (I12)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_ids_are_no_information_404s() {
    let server = spawn_fixtures().await;
    let untp_response = get(
        &server.base_url,
        "/untp/product/urn:unidpp:passport:does-not-exist",
    )
    .await;
    let en_response = get(
        &server.base_url,
        "/en18222/v1/dppsByProductId/9999999999999",
    )
    .await;
    assert_eq!(untp_response.status, 404);
    assert_eq!(en_response.status, 404);
    // Identical bytes for both routes — never vary this response.
    assert_eq!(untp_response.body_string(), "{\"error\":\"not found\"}");
    assert_eq!(untp_response.body_string(), en_response.body_string());
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Issuer upstream
// ---------------------------------------------------------------------------

/// Spawn a real `unidpp-issuer`, create a passport with a profile
/// config vector, append a server-signed issuance event, and return
/// the running issuer.
async fn seeded_issuer() -> unidpp_issuer::TestServer {
    let issuer = unidpp_issuer::TestServer::spawn(unidpp_issuer::Config::default())
        .await
        .expect("spawn issuer");
    let created = post_json(
        &issuer.base_url,
        "/passports",
        &json!({
            "identity": "gtin:5012345100036",
            "passport_id": "urn:unidpp:passport:iss-gw-1",
            "eo_id": "eo-gateway-test",
            "capability": "S1",
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_to": "2040-01-01T00:00:00Z",
            "config": ["urn:unidpp:profile:test-lens@9.9.9"],
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.body_string());
    let appended = post_json(
        &issuer.base_url,
        "/passports/urn:unidpp:passport:iss-gw-1/events",
        &json!({"type": "issuance"}),
    )
    .await;
    assert_eq!(appended.status, 201, "{}", appended.body_string());
    issuer
}

#[tokio::test]
async fn issuer_mode_renders_and_verifies_live() {
    let issuer = seeded_issuer().await;
    let gateway = spawn(Some(issuer.base_url.clone())).await;

    let response = get(
        &gateway.base_url,
        "/untp/product/urn:unidpp:passport:iss-gw-1",
    )
    .await;
    assert_eq!(response.status, 200);
    let triad: Value = serde_json::from_str(&response.body_string()).unwrap();
    assert_eq!(triad["rendering"]["source"], "issuer");
    assert_eq!(triad["passport"]["id"], "urn:unidpp:passport:iss-gw-1");
    assert_eq!(triad["passport"]["passportIssuer"]["id"], "eo-gateway-test");
    // The issuer view's config vector becomes the conformity claim.
    assert_eq!(
        triad["passport"]["standardsConformance"][0]["standard"],
        "urn:unidpp:profile:test-lens"
    );
    assert_eq!(
        triad["passport"]["standardsConformance"][0]["conformanceVersion"],
        "9.9.9"
    );
    // The verdict verified the issuer's real Ed25519 event signature
    // against the anchors fetched from GET /keyring.
    assert_eq!(triad["verdict"]["outcome"], "pass");
    assert_eq!(triad["verdict"]["achievedMarker"], "third-party-attested");
    assert_eq!(triad["verdict"]["coverage"]["signatures"]["verified"], 1);
    assert_eq!(triad["verdict"]["coverage"]["anchorCoverage"], 1.0);

    // The EN route renders the issuer passport when addressed by its
    // passport id (the issuer store keys passports by passport id; a
    // bare GTIN is the documented issuer-mode limitation).
    let by_pid = get(
        &gateway.base_url,
        "/en18222/v1/dppsByProductId/urn:unidpp:passport:iss-gw-1?representation=compressed",
    )
    .await;
    assert_eq!(by_pid.status, 200);
    let en: Value = serde_json::from_str(&by_pid.body_string()).unwrap();
    assert_eq!(
        en["digitalProductPassportId"],
        "urn:unidpp:passport:iss-gw-1"
    );
    assert_eq!(
        en["contentSpecificationIds"],
        json!(["EN 18223:2026", "urn:unidpp:profile:test-lens@9.9.9"])
    );

    gateway.stop().await;
    issuer.stop().await;
}

#[tokio::test]
async fn unreachable_issuer_degrades_to_fixtures() {
    // Port 1 on loopback: nothing listens there.
    let server = spawn(Some("http://127.0.0.1:1".into())).await;
    let fixture_response = get(
        &server.base_url,
        &format!("/untp/product/{}", urlenc(LAPTOP_PASSPORT_ID)),
    )
    .await;
    assert_eq!(fixture_response.status, 200);
    let triad: Value = serde_json::from_str(&fixture_response.body_string()).unwrap();
    assert_eq!(triad["rendering"]["source"], "fixture");

    // An id only the (dead) issuer could know: no-information 404.
    let missing = get(
        &server.base_url,
        "/untp/product/urn:unidpp:passport:only-issuer",
    )
    .await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body_string(), "{\"error\":\"not found\"}");
    server.stop().await;
}

/// Percent-encode a path segment (URNs contain `:`).
fn urlenc(s: &str) -> String {
    unidpp_gateway::http::Url::encode_query_component(s)
}

#[tokio::test]
async fn both_bindings_serve_the_same_core_state() {
    // AD-3 / SV-5: binding pluralism — the UNTP render and the EN
    // 18222 render are two bindings of ONE capability, serving the
    // same core state. One passport, both protocols, one identity.
    let server = spawn_fixtures().await;
    let untp = get(
        &server.base_url,
        &format!("/untp/product/{}", urlenc(TYRE_GTIN)),
    )
    .await;
    assert_eq!(untp.status, 200, "the UNTP binding serves the tyre");
    let triad: Value = serde_json::from_str(&untp.body_string()).unwrap();
    let untp_identity = triad["passport"]["productIdentifiers"][0]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("the UNTP render carries the identity"));

    let en = get(
        &server.base_url,
        &format!("/en18222/v1/dppsByProductId/{}", urlenc(TYRE_GTIN)),
    )
    .await;
    assert_eq!(en.status, 200, "the EN 18222 binding serves the tyre");
    let dpp: Value = serde_json::from_str(&en.body_string()).unwrap();
    let en_identity = dpp["uniqueProductIdentifier"]
        .as_str()
        .unwrap_or_else(|| panic!("the EN 18222 render carries the identity: {}", dpp));

    // The UNTP form carries the GS1 AI-delimited form; the EN form
    // the bare key. Both name the same product: the delimited form
    // wraps the bare key.
    let bare = untp_identity
        .rsplit_once(")")
        .map(|(_, rest)| rest)
        .unwrap_or(untp_identity);
    assert_eq!(
        bare, en_identity,
        "both bindings serve the same core state — the identity matches across protocols"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// The consumer report channel (TODO.impl 224 — MobileQR 投诉反馈)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn feedback_is_journaled_receipted_and_rate_gated() {
    let server = TestServer::spawn(Config {
        feedback_rate_per_minute: 2,
        admin_token: Some("s3cret".to_string()),
        ..Config::default()
    })
    .await
    .expect("spawn gateway");
    let base = &server.base_url;

    // A typed report is admitted, journaled, and acknowledged with its
    // sequence and instant — the receipt cites without the contact.
    let body = json!({
        "identifier": "gs1:(01)06901234567892",
        "category": "goods-mismatch",
        "contact": "reporter@example.org",
        "details": "the package says 20 Ah, the page says 0.072 kWh"
    });
    let resp = post_json(base, "/feedback", &body).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let receipt: Value = serde_json::from_str(&resp.body_string()).unwrap();
    assert_eq!(receipt["seq"], json!(1));
    assert_eq!(receipt["category"], json!("goods-mismatch"));
    assert_eq!(receipt["contact"], json!("withheld"));
    assert!(receipt["recorded_at"].as_str().is_some());

    // The public citation form serves the report by sequence, contact
    // withheld (stated, never silent).
    let resp = get(base, "/feedback/1").await;
    assert_eq!(resp.status, 200);
    assert_eq!(json_of(&resp)["contact"], json!("withheld"));
    assert_eq!(json_of(&resp)["identifier"], json!("gs1:(01)06901234567892"));

    // An unstated report is refused with a stated reason.
    let resp = post_json(base, "/feedback", &json!({
        "identifier": " ", "category": "goods-mismatch", "details": "x"
    }))
    .await;
    assert_eq!(resp.status, 400);
    assert!(resp.body_string().contains("`identifier` is required"));

    // The admission gate: at most 2 per identifier per minute — the
    // third is REFUSED WITH A STATED REASON (429), a different
    // identifier is a different window.
    let body2 = json!({
        "identifier": "gs1:(01)06901234567892",
        "category": "advertising-mismatch",
        "details": "the ad claims Qi2, the page does not"
    });
    assert_eq!(post_json(base, "/feedback", &body2).await.status, 201);
    let resp = post_json(base, "/feedback", &body2).await;
    assert_eq!(resp.status, 429);
    assert!(resp.body_string().contains("rate limit"));
    let other = json!({
        "identifier": "gs1:(01)09506000134352",
        "category": "other:labelling",
        "details": "the energy label class is unreadable"
    });
    assert_eq!(post_json(base, "/feedback", &other).await.status, 201);

    // The admin listing carries the contacts; unguarded access is
    // refused when a token is configured.
    let resp = get(base, "/admin/feedback").await;
    assert_eq!(resp.status, 401);
    let resp = json_request(
        "GET",
        &format!("{base}/admin/feedback?limit=10"),
        None,
        Some("s3cret"),
        TIMEOUT,
    )
    .await
    .expect("admin listing");
    assert_eq!(resp.status, 200);
    let listing = json_of(&resp);
    assert_eq!(listing["total"], json!(3));
    assert_eq!(listing["records"][0]["identifier"], json!("gs1:(01)09506000134352"));
    assert!(listing["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["contact"] == json!("reporter@example.org")));

    // An unknown citation is a stated 404.
    let resp = get(base, "/feedback/99").await;
    assert_eq!(resp.status, 404);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// The scan-token gate (TODO.impl 224 — deployment policy, enforced)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_scan_gate_states_itself_and_opens_under_policy() {
    // Policy on: TTL 60 s, 2 issuances per source per minute.
    let server = TestServer::spawn(Config {
        scan_ttl_secs: 60,
        scan_limit_per_minute: 2,
        ..Config::default()
    })
    .await
    .expect("spawn gateway");
    let base = &server.base_url;

    // No token: a stated 401 naming the policy and where to get one.
    let resp = get(base, &format!("/untp/product/{LAPTOP_PRODUCT_ID}")).await;
    assert_eq!(resp.status, 401);
    assert!(resp.body_string().contains("scan token required"));
    assert!(resp.body_string().contains("60 s"));

    // Issuance is throttled and states itself; a live token opens the
    // renders.
    let resp = post_json(base, "/scan-tokens", &json!({"source": "test-a"})).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let token = json_of(&resp)["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("scan-"));
    let resp = json_request(
        "GET",
        &format!("{base}/untp/product/{LAPTOP_PRODUCT_ID}"),
        None,
        None,
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(resp.status, 401); // sanity: still gated without it
    let resp = unidpp_gateway::http::request(
        "GET",
        &unidpp_gateway::http::Url::parse(&format!(
            "{base}/untp/product/{LAPTOP_PRODUCT_ID}"
        ))
        .unwrap(),
        &[("x-unidpp-scan".to_string(), token.clone())],
        None,
        TIMEOUT,
    )
    .await
    .expect("tokened render");
    assert_eq!(resp.status, 200);

    // The EN 18222 render is gated the same way.
    let resp = get(base, &format!("/en18222/v1/dppsByProductId/{TYRE_GTIN}")).await;
    assert_eq!(resp.status, 401);

    // Throttle: two issuances per source per minute, one already used.
    assert_eq!(
        post_json(base, "/scan-tokens", &json!({"source": "test-a"})).await.status,
        201
    );
    let resp = post_json(base, "/scan-tokens", &json!({"source": "test-a"})).await;
    assert_eq!(resp.status, 429);
    assert!(resp.body_string().contains("issuance limit"));
    // A different source has its own window.
    assert_eq!(
        post_json(base, "/scan-tokens", &json!({"source": "test-b"})).await.status,
        201
    );

    server.stop().await;

    // Policy off (the default doctrine: public resolution): open.
    let open = spawn_fixtures().await;
    let resp = get(&open.base_url, &format!("/untp/product/{LAPTOP_PRODUCT_ID}")).await;
    assert_eq!(resp.status, 200);
    // And issuance states that the gate is open.
    let resp = post_json(&open.base_url, "/scan-tokens", &json!({"source": "x"})).await;
    assert_eq!(resp.status, 409);
    assert!(resp.body_string().contains("no scan policy"));
    assert_eq!(json_of(&resp)["gate"], json!("open"));
    open.stop().await;
}
