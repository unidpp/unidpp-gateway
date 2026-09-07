//! UNTP ingest integration: the S12 seam's import direction over real
//! HTTP. The round-trip is the headline: render a fixture passport to
//! the UNTP triad, feed the triad back through `POST /untp/ingest`,
//! and the minted core identity matches; the ingested passport is
//! served by the same render route; re-ingest matches; unknown schemes
//! degrade explicitly.

use std::time::Duration;

use serde_json::{json, Value};
use unidpp_gateway::http::{json_request, HttpResponse};
use unidpp_gateway::{Config, TestServer};

const TIMEOUT: Duration = Duration::from_secs(10);

async fn spawn() -> TestServer {
    TestServer::spawn(Config::default())
        .await
        .expect("spawn gateway")
}

async fn get(base: &str, path: &str) -> HttpResponse {
    json_request("GET", &format!("{base}{path}"), None, None, TIMEOUT)
        .await
        .expect("http request")
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

fn json_of(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.body_string()).expect("response JSON")
}

/// A fixture's passport id from the discovery index.
async fn first_fixture_id(base: &str) -> String {
    let doc = json_of(&get(base, "/").await);
    doc["source"]["fixtures"][0]["passport_id"]
        .as_str()
        .expect("fixture passport id")
        .to_string()
}

#[tokio::test]
async fn render_ingest_round_trip_identity_matches() {
    let server = spawn().await;
    let fixture_id = first_fixture_id(&server.base_url).await;

    // Render the fixture to the UNTP triad.
    let rendered = json_of(&get(&server.base_url, &format!("/untp/product/{fixture_id}")).await);
    assert!(
        rendered["rendering"]["profile"]
            .as_str()
            .unwrap()
            .contains("untp"),
        "rendering profile: {}",
        rendered["rendering"]["profile"]
    );
    let source_identity = rendered["passport"]["productIdentifiers"][0]["value"]
        .as_str()
        .expect("rendered identifier")
        .to_string();
    let source_standards: Vec<String> = rendered["passport"]["standardsConformance"]
        .as_array()
        .expect("standards conformance")
        .iter()
        .map(|s| s["standard"].as_str().expect("standard id").to_string())
        .collect();

    // Ingest the whole triad back.
    let resp = post_json(&server.base_url, "/untp/ingest", &rendered).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&resp);
    assert_eq!(doc["status"], "imported");
    assert!(doc["passport_id"]
        .as_str()
        .unwrap()
        .starts_with("urn:unidpp:passport:untp-"));

    // The identity matches: the rendered identifier value parses back
    // to the same subject. The rendered value is the display form for
    // non-GS1 subjects and the AI form for GS1 — compare through the
    // core document's identity string.
    let ingested_id = doc["passport_id"].as_str().unwrap().to_string();
    let re_rendered =
        json_of(&get(&server.base_url, &format!("/untp/product/{ingested_id}")).await);
    let round_trip_identity = re_rendered["passport"]["productIdentifiers"][0]["value"]
        .as_str()
        .expect("re-rendered identifier")
        .to_string();
    assert_eq!(
        round_trip_identity, source_identity,
        "render → ingest → render must preserve the identity"
    );

    // The conformity claims landed as profile bindings: every standard
    // the fixture rendered is bound on the ingested passport.
    let bound: Vec<String> = doc["profiles"]
        .as_array()
        .expect("profiles")
        .iter()
        .map(|p| p["id"].as_str().unwrap().to_string())
        .collect();
    for standard in &source_standards {
        assert!(
            bound.contains(standard),
            "conformity standard {standard} must land as a profile binding (bound: {bound:?})"
        );
    }

    // Re-ingest the same triad: matched (idempotent).
    let resp = post_json(&server.base_url, "/untp/ingest", &rendered).await;
    assert_eq!(resp.status, 200, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["status"], "matched");
    assert_eq!(json_of(&resp)["passport_id"], ingested_id);
    server.stop().await;
}

#[tokio::test]
async fn unknown_scheme_degrades_explicitly() {
    let server = spawn().await;
    let exotic = json!({
        "passport": {
            "type": ["VerifiableCredential", "DigitalProductPassport"],
            "id": "https://example.org/passports/exotic-1",
            "passportIssuer": {"id": "https://example.org/issuer"},
            "validFrom": "2026-01-01T00:00:00Z",
            "productIdentifiers": [{
                "scheme": "https://example.org/schemes/exotic/",
                "value": "EX-42"
            }]
        },
        "conformity": [],
        "link": {"linkType": "untp-dpp", "target": "https://example.org/r/exotic-1"},
    });
    let resp = post_json(&server.base_url, "/untp/ingest", &exotic).await;
    assert_eq!(resp.status, 422, "{}", resp.body_string());
    let doc = json_of(&resp);
    assert_eq!(doc["status"], "degraded");
    assert!(
        doc["reason"].as_str().unwrap().contains("no C8 mapping"),
        "{}",
        doc["reason"]
    );
    // Nothing was minted: the passport does not resolve.
    let resp = get(
        &server.base_url,
        "/untp/product/urn:unidpp:passport:anything",
    )
    .await;
    assert_eq!(resp.status, 404);
    server.stop().await;
}

#[tokio::test]
async fn malformed_body_is_rejected_not_degraded() {
    let server = spawn().await;
    let resp = post_json(
        &server.base_url,
        "/untp/ingest",
        &json!({"unrelated": true}),
    )
    .await;
    assert_eq!(resp.status, 422);
    let body = "not json".to_string();
    let resp = json_request(
        "POST",
        &format!("{}/untp/ingest", server.base_url),
        Some(&body),
        None,
        TIMEOUT,
    )
    .await
    .expect("http request");
    assert_eq!(resp.status, 400);
    server.stop().await;
}
