//! HTTP surface: axum router, handlers, `Config`, `TestServer`.
//!
//! Conventions (mirroring `unidpp-issuer` / `unidpp-gate`): every
//! response is as-of stamped (`x-as-of` header); not-found responses
//! are no-information — identical bytes for unknown passports and
//! anything deliberately unresolvable (I12 enumeration resistance).
//! One deliberate deviation, documented: the EN 18222 render body
//! carries **no** `as_of` member — its wire field set is frozen to the
//! EN/freeDPP artifact shape; the stamp rides the `x-as-of` header
//! instead.
//!
//! | endpoint | purpose |
//! |---|---|
//! | `POST /untp/ingest` | the import direction: a UNTP passport VC (bare or triad) mints a core passport with a deterministic identity; conformity → profile bindings |
//! | `GET /untp/product/{id}` | the UNTP verifiable-credential triad (passport VC + conformity credentials + link-resolver entry) with the py-adapter verdict |
//! | `GET /en18222/v1/dppsByProductId/{gtin}?representation=full\|compressed` | the EN 18222 REST render (default compressed, per the EN) |
//! | `GET /healthz` | liveness |
//! | `GET /` | discovery: both bindings documented as C4 protocol renderings |

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use unidpp_model::Timestamp;

use crate::en18222::{self, Representation};
use crate::source::PassportSource;
use crate::untp;

/// The no-information 404: identical bytes for unknown passports and
/// anything deliberately unresolvable alike (I12). Never vary this
/// response.
pub const NOT_FOUND_BODY: &str = "{\"error\":\"not found\"}";

/// Deployment configuration (environment-driven; see `main.rs`).
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address.
    pub bind: SocketAddr,
    /// Optional issuer upstream base URL (`UNIDPP_ISSUER_URL`; alias
    /// `UNIDPP_GATEWAY_ISSUER_URL`).
    pub issuer_url: Option<String>,
    /// Upstream request timeout.
    pub timeout: Duration,
    /// The consumer-report journal path (`UNIDPP_GATEWAY_FEEDBACK_JOURNAL`);
    /// absent = in-memory only (dev).
    pub feedback_journal: Option<std::path::PathBuf>,
    /// Per-identifier report rate limit (`UNIDPP_GATEWAY_FEEDBACK_RATE`,
    /// reports per minute); 0/absent = permissive.
    pub feedback_rate_per_minute: usize,
    /// Admin bearer token (`UNIDPP_GATEWAY_ADMIN_TOKEN`) guarding the
    /// report listing.
    pub admin_token: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8094".parse().expect("static bind"),
            issuer_url: None,
            timeout: Duration::from_secs(2),
            feedback_journal: None,
            feedback_rate_per_minute: 0,
            admin_token: None,
        }
    }
}

impl Config {
    /// Resolve configuration from environment variables.
    pub fn from_env() -> Config {
        let mut config = Config::default();
        if let Ok(bind) = std::env::var("UNIDPP_GATEWAY_BIND") {
            match bind.parse() {
                Ok(addr) => config.bind = addr,
                Err(_) => eprintln!("unidpp-gateway: ignoring bad UNIDPP_GATEWAY_BIND `{bind}`"),
            }
        }
        // The task-facing name is UNIDPP_ISSUER_URL; the service-
        // scoped alias keeps the house naming convention available.
        for key in ["UNIDPP_ISSUER_URL", "UNIDPP_GATEWAY_ISSUER_URL"] {
            if let Ok(url) = std::env::var(key) {
                if !url.trim().is_empty() {
                    config.issuer_url = Some(url);
                    break;
                }
            }
        }
        if let Ok(path) = std::env::var("UNIDPP_GATEWAY_FEEDBACK_JOURNAL") {
            if !path.trim().is_empty() {
                config.feedback_journal = Some(std::path::PathBuf::from(path));
            }
        }
        if let Ok(rate) = std::env::var("UNIDPP_GATEWAY_FEEDBACK_RATE") {
            match rate.trim().parse::<usize>() {
                Ok(n) => config.feedback_rate_per_minute = n,
                Err(_) => eprintln!(
                    "unidpp-gateway: ignoring bad UNIDPP_GATEWAY_FEEDBACK_RATE `{rate}`"
                ),
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_GATEWAY_ADMIN_TOKEN") {
            if !token.trim().is_empty() {
                config.admin_token = Some(token);
            }
        }
        if let Ok(ms) = std::env::var("UNIDPP_GATEWAY_TIMEOUT_MS") {
            match ms.trim().parse::<u64>() {
                Ok(ms) => config.timeout = Duration::from_millis(ms),
                Err(_) => {
                    eprintln!("unidpp-gateway: ignoring bad UNIDPP_GATEWAY_TIMEOUT_MS `{ms}`")
                }
            }
        }
        config
    }
}

/// Shared application state.
pub struct AppState {
    /// Deployment configuration.
    pub config: Config,
    /// The passport data source (fixtures + optional issuer upstream).
    pub source: PassportSource,
    /// Passports ingested from UNTP triads (`POST /untp/ingest`).
    pub ingested: std::sync::Mutex<crate::ingest::IngestStore>,
    /// The consumer-report journal (TODO.impl 224).
    pub feedback: std::sync::Mutex<crate::feedback::FeedbackStore>,
    /// The pluggable admission gate in front of the report path.
    pub admission: std::sync::Arc<dyn crate::feedback::AdmissionControl>,
}

impl AppState {
    /// Assemble state from a config.
    pub fn new(config: Config) -> AppState {
        let admission: std::sync::Arc<dyn crate::feedback::AdmissionControl> =
            if config.feedback_rate_per_minute > 0 {
                std::sync::Arc::new(crate::feedback::RateLimited::per_minute(
                    config.feedback_rate_per_minute,
                ))
            } else {
                std::sync::Arc::new(crate::feedback::Permissive)
            };
        let feedback = crate::feedback::FeedbackStore::open(config.feedback_journal.as_deref())
            .unwrap_or_else(|e| {
                eprintln!("unidpp-gateway: feedback journal unavailable ({e}); in-memory only");
                crate::feedback::FeedbackStore::open(None).expect("in-memory store")
            });
        AppState {
            source: PassportSource::new(config.issuer_url.clone()),
            ingested: std::sync::Mutex::new(crate::ingest::IngestStore::new()),
            feedback: std::sync::Mutex::new(feedback),
            admission,
            config,
        }
    }
}

/// POST /feedback — the consumer report channel (TODO.impl 224):
/// a stated report path on the public edge. The typed categories are
/// MobileQR's two (goods-mismatch 实物不符 / advertising-mismatch 宣传
/// 不符) plus a stated free-form other; admission control is the
/// deployment's pluggable choice (a rate window here; captcha + SMS
/// behind the same trait in a deployment that runs them); every
/// admitted report is journaled and acknowledged with its sequence
/// and instant.
async fn submit_feedback(
    State(app): State<Arc<AppState>>,
    body: String,
) -> Response {
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&format!("invalid JSON body: {e}")),
    };
    let report = crate::feedback::FeedbackReport {
        identifier: v
            .get("identifier")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        category: crate::feedback::FeedbackCategory::parse(
            v.get("category").and_then(Value::as_str).unwrap_or(""),
        ),
        contact: v
            .get("contact")
            .and_then(Value::as_str)
            .filter(|c| !c.trim().is_empty())
            .map(str::to_string),
        details: v
            .get("details")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    };
    if let Err(reason) = app.admission.admit(&report) {
        return build_response(
            StatusCode::TOO_MANY_REQUESTS,
            vec![("content-type".into(), "application/json".into())],
            json!({ "error": reason, "refused": true }).to_string(),
        );
    }
    let now = Timestamp::now().to_string();
    let rec = {
        let mut feedback = app.feedback.lock().expect("feedback store poisoned");
        match feedback.submit(report, &now) {
            Ok(rec) => rec,
            Err(e) => return bad_request(&e),
        }
    };
    build_response(
        StatusCode::CREATED,
        vec![("content-type".into(), "application/json".into())],
        rec.to_json(false).to_string(),
    )
}

/// GET /feedback/{seq} — the public citation form: the report by
/// sequence with the contact withheld (stated, never silent).
async fn feedback_citation(Path(seq): Path<u64>, State(app): State<Arc<AppState>>) -> Response {
    let doc = {
        let feedback = app.feedback.lock().expect("feedback store poisoned");
        feedback.get(seq)
    };
    match doc {
        Some(doc) => build_response(
            StatusCode::OK,
            vec![("content-type".into(), "application/json".into())],
            serde_json::to_string_pretty(&doc).unwrap(),
        ),
        None => not_found(),
    }
}

/// GET /admin/feedback?limit&offset — the full listing (contacts
/// included), newest first, admin-guarded when a token is configured.
async fn feedback_admin(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(token) = &app.config.admin_token {
        let got = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if got != Some(token.as_str()) {
            return build_response(
                StatusCode::UNAUTHORIZED,
                vec![("content-type".into(), "application/json".into())],
                "{\"error\":\"unauthorized\"}".to_string(),
            );
        }
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(10_000);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let doc = {
        let feedback = app.feedback.lock().expect("feedback store poisoned");
        feedback.list_json(limit, offset)
    };
    build_response(
        StatusCode::OK,
        vec![("content-type".into(), "application/json".into())],
        serde_json::to_string_pretty(&doc).unwrap(),
    )
}

/// Resolve a passport from any serving source: fixtures, the issuer
/// upstream, then the ingested store.
async fn resolve_any(app: &Arc<AppState>, id: &str) -> Option<crate::source::GatewayPassport> {
    if let Some(found) = app.source.resolve(id).await {
        return Some(found);
    }
    let ingested = app.ingested.lock().expect("ingest store poisoned");
    ingested.resolve(id).cloned()
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn build_response(status: StatusCode, headers: Vec<(String, String)>, body: String) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

/// A JSON response carrying its own as-of stamp (header + `as_of`
/// body member, the house convention).
fn stamped(status: StatusCode, body: &Value, as_of: Timestamp) -> Response {
    let mut body = body.clone();
    if let Some(m) = body.as_object_mut() {
        m.insert("as_of".into(), json!(as_of.to_string()));
    }
    build_response(
        status,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), as_of.to_string()),
        ],
        serde_json::to_string_pretty(&body).unwrap(),
    )
}

/// A wire-shaped JSON response whose body must not be augmented (the
/// EN 18222 render): the stamp rides the header only.
fn wire_stamped(status: StatusCode, body: &Value, as_of: Timestamp) -> Response {
    build_response(
        status,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), as_of.to_string()),
        ],
        serde_json::to_string_pretty(body).unwrap(),
    )
}

fn bad_request(msg: &str) -> Response {
    stamped(
        StatusCode::BAD_REQUEST,
        &json!({ "error": msg }),
        Timestamp::now(),
    )
}

/// The no-information 404.
fn not_found() -> Response {
    build_response(
        StatusCode::NOT_FOUND,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), Timestamp::now().to_string()),
        ],
        NOT_FOUND_BODY.to_string(),
    )
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn discovery(State(app): State<Arc<AppState>>) -> Response {
    let doc = json!({
        "service": "unidpp-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "build_id": option_env!("UNIDPP_BUILD_ID").unwrap_or("dev"),
        "description": "UniDPP interop gateway: renders the neutral core in foreign protocol shapes — \
                        their format is our profile. The py \
                        adapters are the semantics source; this service ports them and serves both \
                        renderings from one core.",
        "endpoints": {
            "untp": "GET /untp/product/{id}?freshness=",
            "untp_ingest": "POST /untp/ingest (import direction: a UNTP passport VC or triad mints a core passport with a deterministic identity; idempotent per subject)",
            "en18222": "GET /en18222/v1/dppsByProductId/{gtin}?representation=full|compressed",
            "feedback": "POST /feedback {identifier, category: goods-mismatch|advertising-mismatch|other:<stated>, contact?, details<=500} — the consumer report channel: journaled, sequenced, receipted; admission control is deployment-pluggable (rate window via UNIDPP_GATEWAY_FEEDBACK_RATE; refusals state their reason)",
            "feedback_citation": "GET /feedback/{seq} — the public citation form (contact withheld, stated)",
            "feedback_admin": "GET /admin/feedback?limit=&offset= — the full listing, admin-guarded when UNIDPP_GATEWAY_ADMIN_TOKEN is set",
            "health": "GET /healthz",
        },
        "bindings": {
            "untp": {
                "endpoint": "GET /untp/product/{id}",
                "profile": untp::UNTP_PROFILE,
                "rendering": "UNTP verifiable-credential triad: DigitalProductPassport VC (the py stub shape) \
                              + DigitalConformityCredentials (profile bindings + E14 inspection stamps) \
                              + link-resolver entry (log-head anchored)",
                "semantics": "port of unidpp-py/unidpp/adapters/untp.py (parse_stub kept for round-trip) \
                              with the verify.py verdict rules over the evidence",
                "identifier_mapping": "core cpid <-> https://unidpp.org/id/ (py iso-15459); gs1 family \
                              <-> https://gs1.org/voc/ with (01)/(10)/(21) application identifiers",
            },
            "en18222": {
                "endpoint": "GET /en18222/v1/dppsByProductId/{gtin}",
                "profile": en18222::EN18222_PROFILE,
                "rendering": "the EN 18222 REST shape: full (element tree, string-printed values) or \
                              compressed (collection-keyed, native JSON values); default compressed per the EN",
                "semantics": "wire field set mirrored from the freeDPP live-endpoint artifacts \
                              (unidpp-py/conformance/competitors/freedpp/artifacts/*-api-{full,compressed}.json)",
            },
        },
        "c4": "both bindings are C4 protocol renderings of one neutral core — no region is the \
               universal envelope; adding a protocol adds a render profile, never a fork",
        "source": {
            "issuer_url": app.config.issuer_url,
            "mode": if app.config.issuer_url.is_some() { "issuer-upstream-with-fixture-fallback" } else { "fixtures" },
            "fixtures": app.source.fixture_index(),
        },
        "conventions": [
            "as-of stamped responses (x-as-of header; as_of body member except on the frozen EN 18222 wire)",
            "no-information 404s: identical bytes for unknown and deliberately unresolvable ids (I12)",
            "the gateway renders core passports in foreign shapes, and imports them back with a \
             deterministic identity (render and ingest are inverse projections; imported documents \
             carry an empty log — their events live in the source regime, the receipt records the origin)",
        ],
    });
    stamped(StatusCode::OK, &doc, Timestamp::now())
}

async fn healthz() -> Response {
    build_response(
        StatusCode::OK,
        vec![
            ("content-type".into(), "text/plain".into()),
            ("x-as-of".into(), Timestamp::now().to_string()),
        ],
        "ok".into(),
    )
}

/// GET /untp/product/{id} — the verifiable-credential triad + verdict.
async fn untp_product(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(id): Path<String>,
) -> Response {
    let required_freshness = params
        .get("freshness")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(freshness) = &required_freshness {
        if crate::verdict::duration_to_ms(freshness).is_none() {
            return bad_request("`freshness` must be an ISO 8601 duration (PnDTnHnMnS)");
        }
    }
    let Some(passport) = resolve_any(&app, &id).await else {
        return not_found();
    };
    let now = Timestamp::now();
    let triad = untp::render_triad(&passport, now, required_freshness.as_deref());
    stamped(StatusCode::OK, &triad, now)
}

/// GET /en18222/v1/dppsByProductId/{gtin} — the EN 18222 REST render.
async fn en18222_dpps(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(gtin): Path<String>,
) -> Response {
    let representation =
        match Representation::parse(params.get("representation").map(String::as_str)) {
            Ok(representation) => representation,
            Err(e) => return bad_request(&e),
        };
    let Some(passport) = app.source.resolve_gtin(&gtin).await else {
        return not_found();
    };
    let now = Timestamp::now();
    let rendered = en18222::render(&passport, representation, now);
    wire_stamped(StatusCode::OK, &rendered, now)
}

/// POST /untp/ingest — the import direction: a UNTP passport VC (bare
/// or the triad this gateway renders) mints a neutral-core passport
/// with a deterministic identity; conformity credentials land as
/// profile bindings. Idempotent per subject identity.
async fn untp_ingest(State(app): State<Arc<AppState>>, body: String) -> Response {
    let stub: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&format!("invalid JSON body: {e}")),
    };
    let now = Timestamp::now();
    let outcome = {
        let mut store = app.ingested.lock().expect("ingest store poisoned");
        store.ingest(&stub, now)
    };
    match outcome {
        Ok(outcome) => {
            let status = match outcome.status {
                crate::ingest::IngestStatus::Imported => StatusCode::CREATED,
                crate::ingest::IngestStatus::Matched => StatusCode::OK,
            };
            let document = &outcome.passport.document;
            stamped(
                status,
                &json!({
                    "status": outcome.status.as_str(),
                    "passport_id": document.passport_id.as_str(),
                    "identity": document.product_id.to_string(),
                    "granularity": document.product_id.granularity.to_string(),
                    "profiles": outcome
                        .profiles
                        .iter()
                        .map(|profile| {
                            json!({
                                "id": profile.id,
                                "version": profile.version,
                                "effective_from": profile.effective_from.map(|t| t.to_string()),
                            })
                        })
                        .collect::<Vec<_>>(),
                    "receipt": outcome.receipt,
                }),
                now,
            )
        }
        Err(reason) => stamped(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({
                "status": "degraded",
                "reason": reason,
            }),
            now,
        ),
    }
}

// ---------------------------------------------------------------------------
// Route wiring
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/untp/product/{id}", get(untp_product))
        .route("/untp/ingest", post(untp_ingest))
        .route("/en18222/v1/dppsByProductId/{gtin}", get(en18222_dpps))
        .route("/feedback", post(submit_feedback))
        .route("/feedback/{seq}", get(feedback_citation))
        .route("/admin/feedback", get(feedback_admin))
        .with_state(app)
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> std::io::Result<()> {
    let bind = config.bind;
    let app = Arc::new(AppState::new(config));
    let listener = TcpListener::bind(bind).await?;
    eprintln!("unidpp-gateway listening on http://{bind}");
    axum::serve(listener, router(app)).await
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    /// The bound address.
    pub addr: SocketAddr,
    /// `http://host:port` base URL.
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    /// Spawn with a config (the bind address is replaced by an
    /// ephemeral loopback port).
    pub async fn spawn(config: Config) -> std::io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Config {
            bind: addr,
            ..config
        };
        let app = Arc::new(AppState::new(config));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-gateway: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    /// Stop the server and wait until its listener is released.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_starts_and_serves_discovery() {
        let server = TestServer::spawn(Config::default()).await.expect("spawn");
        let response = crate::http::json_request(
            "GET",
            &format!("{}/", server.base_url),
            None,
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("discovery request");
        assert_eq!(response.status, 200);
        let doc: Value = serde_json::from_str(&response.body_string()).unwrap();
        assert_eq!(doc["service"], "unidpp-gateway");
        server.stop().await;
    }
}
