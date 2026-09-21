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
//! | `POST /feedback` | the consumer report channel (typed goods-mismatch/advertising-mismatch/other): journaled, receipted; admission control deployment-pluggable |
//! | `GET /feedback/{seq}` | the public citation form (contact withheld, stated) |
//! | `GET /admin/feedback?limit=&offset=` | the full listing (admin-guarded when a token is configured) |
//! | `POST /scan-tokens` | issue a scan token under the configured scan policy (absent policy = the gate is open; refusals state themselves) |

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
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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
    /// The scan-token policy (TODO.impl 224): TTL seconds and issuance
    /// limit per source per minute (0 = off — the public-resolution
    /// default; rendered by unidpp-config from the manifest).
    pub scan_ttl_secs: u64,
    pub scan_limit_per_minute: usize,
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
            scan_ttl_secs: 0,
            scan_limit_per_minute: 0,
        }
    }
}

impl Config {
    /// Resolve configuration from environment variables.
    /// The environment variables this service consumes. This is the
    /// deployment contract: unidpp-config renders exactly these names
    /// for the gateway, and the contract document carries them as
    /// `x-unidpp-env-keys`. `UNIDPP_ISSUER_URL` and its service-scoped
    /// alias name one setting (the task-facing name wins).
    pub const ENV_KEYS: &'static [&'static str] = &[
        "UNIDPP_GATEWAY_BIND",
        "UNIDPP_ISSUER_URL",
        "UNIDPP_GATEWAY_ISSUER_URL",
        "UNIDPP_GATEWAY_FEEDBACK_JOURNAL",
        "UNIDPP_GATEWAY_FEEDBACK_RATE",
        "UNIDPP_GATEWAY_ADMIN_TOKEN",
        "UNIDPP_GATEWAY_SCAN_TTL_SECS",
        "UNIDPP_GATEWAY_SCAN_LIMIT_PER_MIN",
        "UNIDPP_GATEWAY_TIMEOUT_MS",
    ];

    pub fn from_env() -> Config {
        let mut config = Config::default();
        let mut vars: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
        for key in Self::ENV_KEYS {
            if let Ok(value) = std::env::var(key) {
                vars.insert(*key, value);
            }
        }
        if let Some(bind) = vars.get("UNIDPP_GATEWAY_BIND") {
            match bind.parse() {
                Ok(addr) => config.bind = addr,
                Err(_) => eprintln!("unidpp-gateway: ignoring bad UNIDPP_GATEWAY_BIND `{bind}`"),
            }
        }
        // The task-facing name is UNIDPP_ISSUER_URL; the service-
        // scoped alias keeps the house naming convention available.
        for key in ["UNIDPP_ISSUER_URL", "UNIDPP_GATEWAY_ISSUER_URL"] {
            if let Some(url) = vars.get(key) {
                if !url.trim().is_empty() {
                    config.issuer_url = Some(url.clone());
                    break;
                }
            }
        }
        if let Some(path) = vars.get("UNIDPP_GATEWAY_FEEDBACK_JOURNAL") {
            if !path.trim().is_empty() {
                config.feedback_journal = Some(std::path::PathBuf::from(path));
            }
        }
        if let Some(rate) = vars.get("UNIDPP_GATEWAY_FEEDBACK_RATE") {
            match rate.trim().parse::<usize>() {
                Ok(n) => config.feedback_rate_per_minute = n,
                Err(_) => {
                    eprintln!("unidpp-gateway: ignoring bad UNIDPP_GATEWAY_FEEDBACK_RATE `{rate}`")
                }
            }
        }
        if let Some(token) = vars.get("UNIDPP_GATEWAY_ADMIN_TOKEN") {
            if !token.trim().is_empty() {
                config.admin_token = Some(token.clone());
            }
        }
        if let Some(ttl) = vars.get("UNIDPP_GATEWAY_SCAN_TTL_SECS") {
            match ttl.trim().parse::<u64>() {
                Ok(t) => config.scan_ttl_secs = t,
                Err(_) => {
                    eprintln!("unidpp-gateway: ignoring bad UNIDPP_GATEWAY_SCAN_TTL_SECS `{ttl}`")
                }
            }
        }
        if let Some(limit) = vars.get("UNIDPP_GATEWAY_SCAN_LIMIT_PER_MIN") {
            match limit.trim().parse::<usize>() {
                Ok(n) => config.scan_limit_per_minute = n,
                Err(_) => eprintln!(
                    "unidpp-gateway: ignoring bad UNIDPP_GATEWAY_SCAN_LIMIT_PER_MIN `{limit}`"
                ),
            }
        }
        if let Some(ms) = vars.get("UNIDPP_GATEWAY_TIMEOUT_MS") {
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
    /// The scan-token gate (ephemeral edge state; off unless policy).
    pub scan: std::sync::Mutex<crate::scan::ScanGate>,
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
            scan: std::sync::Mutex::new(crate::scan::ScanGate::new(crate::scan::ScanPolicy {
                token_ttl_secs: config.scan_ttl_secs,
                issue_limit_per_minute: config.scan_limit_per_minute,
            })),
            config,
        }
    }
}

/// POST /scan-tokens {source} — issue a scan token under the
/// configured policy (the gate states where the policy came from; no
/// policy configured = the gate is open and issuance is a stated
/// no-op). The source names the requester in production set by the
/// fronting proxy (X-UniDPP-Source is accepted here).
/// Issue a scan token (the scan-policy gate: a scan-gated deployment
/// answers unauthenticated mark reads with a stated 401 naming this
/// endpoint; absent policy, reads are free).
#[utoipa::path(
    post,
    path = "/scan-tokens",
    tag = "gateway",
    request_body(content = Value, description = "The issuance request under the deployment's scan policy (rate and ttl are manifest data)"),
    responses(
        (status = 201, description = "Issued; the token and its expiry are stated", body = Value, content_type = "application/json"),
        (status = 401, description = "The issuance credential is required and absent"),
        (status = 429, description = "The policy's per-minute limit is reached"),
    )
)]

async fn issue_scan_token(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let source = headers
        .get("x-unidpp-source")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| v.get("source").and_then(Value::as_str).map(str::to_string))
        })
        .unwrap_or_else(|| "anonymous".to_string());
    let issued = app.scan.lock().expect("scan gate poisoned").issue(&source);
    match issued {
        Ok((token, ttl)) => build_response(
            StatusCode::CREATED,
            vec![("content-type".into(), "application/json".into())],
            json!({ "token": token, "ttl_secs": ttl, "source": source }).to_string(),
        ),
        Err(reason) if reason.starts_with("scan-token issuance limit") => {
            crate::scan::refusal(&reason, true)
        }
        // No policy configured: there is nothing to issue — stated,
        // and not an authentication failure.
        Err(reason) => build_response(
            StatusCode::CONFLICT,
            vec![("content-type".into(), "application/json".into())],
            json!({ "error": reason, "gate": "open" }).to_string(),
        ),
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
/// File a consumer report through the report channel (typed,
/// journaled, receipted; the pluggable admission control decides
/// what a flood is).
#[utoipa::path(
    post,
    path = "/feedback",
    tag = "gateway",
    request_body(content = Value, description = "The report: its type, the subject identifier and the statement"),
    responses(
        (status = 201, description = "Filed; the receipt carries the sequence number that cites it", body = Value, content_type = "application/json"),
        (status = 400, description = "An unparseable or mistyped report"),
        (status = 429, description = "The admission control refused the report as a flood"),
    )
)]

async fn submit_feedback(State(app): State<Arc<AppState>>, body: String) -> Response {
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
/// Retrieve one filed report by its receipt sequence number.
#[utoipa::path(
    get,
    path = "/feedback/{seq}",
    tag = "gateway",
    params(("seq" = u64, Path, description = "The receipt sequence number")),
    responses(
        (status = 200, description = "The report, byte-identical on every read", body = Value, content_type = "application/json"),
        (status = 404, description = "No report carries this sequence number"),
    )
)]

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
/// The operator's window onto the report channel.
#[utoipa::path(
    get,
    path = "/admin/feedback",
    tag = "admin",
    responses(
        (status = 200, description = "The listing of filed reports", body = Value, content_type = "application/json"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]

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

/// Serve the discovery document.
#[utoipa::path(
    get,
    path = "/",
    tag = "gateway",
    responses(
        (status = 200, description = "The discovery document: the served profiles, their endpoint references, the source posture and the response conventions", body = Value, content_type = "application/json"),
    )
)]

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
            "scan_tokens": "POST /scan-tokens {source} — issue a scan token when a scan policy is configured (X-UniDPP-Source honored); TTL + issuance limit are deployment data (unidpp-config scan_policy); absent policy = the gate is open (public resolution is the default doctrine); refusals state themselves (401 absent/unknown/expired, 429 over limit)",
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

/// Liveness probe.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "gateway",
    responses(
        (status = 200, description = "The service is serving"),
    )
)]

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
/// Render one passport in the UNTP verifiable-credential triad
/// (DigitalProductPassport VC + DigitalConformityCredentials + the
/// link-resolver entry) — one neutral core, a C4 protocol rendering.
#[utoipa::path(
    get,
    path = "/untp/product/{id}",
    tag = "gateway",
    params(("id" = String, Path, description = "The product identifier (core cpid or GS1 family element string)")),
    responses(
        (status = 200, description = "The UNTP triad, as-of stamped", body = Value, content_type = "application/json"),
        (status = 404, description = "The no-information 404: identical bytes for unknown and deliberately unresolvable ids (I12)"),
    )
)]

async fn untp_product(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Path(id): Path<String>,
) -> Response {
    if let Err(reason) = app.scan.lock().expect("scan gate poisoned").admit(&headers) {
        return crate::scan::refusal(&reason, false);
    }
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
/// Render passports for a GTIN in the EN 18222 REST shape (full or
/// compressed; the default is compressed per the EN).
#[utoipa::path(
    get,
    path = "/en18222/v1/dppsByProductId/{gtin}",
    tag = "gateway",
    params(
        ("gtin" = String, Path, description = "The GTIN"),
        ("rendering" = Option<String>, Query, description = "`full` (element tree, string-printed values) or `compressed` (collection-keyed, native JSON values; the default)"),
    ),
    responses(
        (status = 200, description = "The EN 18222 document, as-of stamped", body = Value, content_type = "application/json"),
        (status = 404, description = "The no-information 404 (I12)"),
    )
)]

async fn en18222_dpps(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Path(gtin): Path<String>,
) -> Response {
    if let Err(reason) = app.scan.lock().expect("scan gate poisoned").admit(&headers) {
        return crate::scan::refusal(&reason, false);
    }
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
/// Ingest a UNTP document back into the neutral core (render and
/// ingest are inverse projections; imported documents carry an empty
/// log and the receipt records the origin).
#[utoipa::path(
    post,
    path = "/untp/ingest",
    tag = "gateway",
    request_body(content = Value, description = "The UNTP document to import"),
    responses(
        (status = 201, description = "Imported (new subject)", body = Value, content_type = "application/json"),
        (status = 200, description = "Matched (the subject already exists; the import is an identity)", body = Value, content_type = "application/json"),
        (status = 422, description = "The document is well-formed JSON but not a conforming UNTP rendering"),
    )
)]

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

// ---------------------------------------------------------------------------
// Interface contract
// ---------------------------------------------------------------------------

/// The routed paths, declared once. The router routes by these
/// constants, the contract document is tested against them, and no
/// route may be declared with a raw literal (the gates enforce both).
pub mod paths {
    pub const ROOT: &str = "/";
    pub const HEALTHZ: &str = "/healthz";
    pub const UNTP_PRODUCT: &str = "/untp/product/{id}";
    pub const UNTP_INGEST: &str = "/untp/ingest";
    pub const EN18222_DPPS: &str = "/en18222/v1/dppsByProductId/{gtin}";
    pub const SCAN_TOKENS: &str = "/scan-tokens";
    pub const FEEDBACK: &str = "/feedback";
    pub const FEEDBACK_CITATION: &str = "/feedback/{seq}";
    pub const ADMIN_FEEDBACK: &str = "/admin/feedback";
    /// The contract document itself (not an operation of the API).
    pub const CONTRACT_YAML: &str = "/openapi.yaml";
}

/// The OpenAPI model: one declaration per handler (`#[utoipa::path]`),
/// from which the served contract, the golden file and Swagger UI all
/// derive.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "UniDPP gateway",
        version = env!("CARGO_PKG_VERSION"),
        description = "The cross-regime gateway: it renders the neutral core in foreign protocol shapes (UNTP verifiable credentials, the EN 18222 REST shape), imports those shapes back with a deterministic identity, and operates the consumer-facing surfaces (the report channel and the scan-policy gate). As-of stamped responses; no-information 404s (I12).",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(
        discovery, healthz, untp_product, untp_ingest, en18222_dpps,
        issue_scan_token, submit_feedback, feedback_citation, feedback_admin,
    ),
    tags(
        (name = "gateway", description = "Protocol renderings, the report channel and the scan-policy gate"),
        (name = "admin", description = "The operator surface over the report channel"),
    )
)]
struct ApiDoc;

/// The contract document: the OpenAPI model plus the deployment keys
/// (`x-unidpp-env-keys`). Served at `/openapi.yaml` and committed as
/// the golden `openapi.yaml`.
pub fn contract_yaml() -> String {
    let mut doc = serde_json::to_value(ApiDoc::openapi()).expect("contract serializes");
    doc["info"]["x-unidpp-env-keys"] = json!(Config::ENV_KEYS);
    serde_yaml::to_string(&doc).expect("contract renders as YAML")
}

async fn openapi_yaml() -> Response {
    build_response(
        StatusCode::OK,
        vec![("content-type".to_string(), "application/yaml".to_string())],
        contract_yaml(),
    )
}

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .route(paths::ROOT, get(discovery))
        .route(paths::HEALTHZ, get(healthz))
        .route(paths::UNTP_PRODUCT, get(untp_product))
        .route(paths::UNTP_INGEST, post(untp_ingest))
        .route(paths::EN18222_DPPS, get(en18222_dpps))
        .route(paths::SCAN_TOKENS, post(issue_scan_token))
        .route(paths::FEEDBACK, post(submit_feedback))
        .route(paths::FEEDBACK_CITATION, get(feedback_citation))
        .route(paths::ADMIN_FEEDBACK, get(feedback_admin))
        .route(paths::CONTRACT_YAML, get(openapi_yaml))
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

// ---------------------------------------------------------------------------
// Contract gates
// ---------------------------------------------------------------------------

#[cfg(test)]
mod contract_gates {
    use super::*;
    use crate::http::{request, Url};
    use std::time::Duration;

    const VERBS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

    /// The contract paths with their documented methods.
    fn documented() -> std::collections::BTreeMap<String, Vec<String>> {
        let doc: Value = serde_yaml::from_str(&contract_yaml()).expect("contract parses");
        doc["paths"]
            .as_object()
            .expect("paths object")
            .iter()
            .map(|(path, item)| {
                let methods = VERBS
                    .iter()
                    .filter(|v| item.get(*v).is_some())
                    .map(|v| v.to_string())
                    .collect();
                (path.clone(), methods)
            })
            .collect()
    }

    #[test]
    fn the_golden_matches_the_committed_contract() {
        assert_eq!(contract_yaml(), include_str!("../openapi.yaml"));
    }

    #[test]
    #[ignore = "regenerates openapi.yaml after a route change: cargo test contract_gates -- --ignored export"]
    fn export_golden() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"),
            contract_yaml(),
        )
        .expect("golden written");
    }

    /// Every path the router serves (the contract route itself
    /// carries no operation).
    fn routed_paths() -> Vec<&'static str> {
        vec![
            paths::ROOT,
            paths::HEALTHZ,
            paths::UNTP_PRODUCT,
            paths::UNTP_INGEST,
            paths::EN18222_DPPS,
            paths::SCAN_TOKENS,
            paths::FEEDBACK,
            paths::FEEDBACK_CITATION,
            paths::ADMIN_FEEDBACK,
        ]
    }

    #[test]
    fn every_routed_path_is_documented() {
        let doc = documented();
        for path in routed_paths() {
            assert!(doc.contains_key(path), "routed but undocumented: {path}");
        }
    }

    #[test]
    fn every_documented_path_is_routed() {
        let routed: std::collections::BTreeSet<String> =
            routed_paths().into_iter().map(str::to_string).collect();
        for path in documented().keys() {
            assert!(routed.contains(path), "documented but not routed: {path}");
        }
    }

    #[test]
    fn routes_are_declared_by_constant_not_literal() {
        let flat: String = include_str!("api.rs")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let mut idx = 0;
        while let Some(pos) = flat[idx..].find(".route(") {
            let abs = idx + pos;
            if abs > 0 && flat.as_bytes()[abs - 1] == b'"' {
                idx = abs + 7;
                continue;
            }
            let after = flat[abs + 7..].trim_start();
            assert!(
                after.starts_with("paths::"),
                "route paths come from the paths:: constants: `{}`",
                &flat[abs..(abs + 60).min(flat.len())]
            );
            idx = abs + 7;
        }
    }

    /// The `VERB /path` endpoint references embedded in the discovery
    /// document must all be contracted operations.
    #[tokio::test]
    async fn discovery_names_only_contracted_endpoints() {
        let ts = TestServer::spawn(Config::default()).await.expect("server");
        let resp = request(
            "GET",
            &Url::parse(&format!("{}/", ts.base_url)).expect("url"),
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("discovery answered");
        ts.stop().await;
        let body = resp.body_string();
        let documented: Vec<String> = documented().into_keys().collect();
        for verb in VERBS.map(str::to_uppercase) {
            let mut rest = body.as_str();
            while let Some(pos) = rest.find(&verb) {
                let after = &rest[pos + verb.len()..];
                rest = after;
                let Some(path) = after.strip_prefix(" /") else {
                    continue;
                };
                let taken: String = path
                    .chars()
                    .take_while(|c| !matches!(c, ' ' | '"' | '<'))
                    .collect();
                let path = taken.split('?').next().unwrap_or("").to_string();
                if path.is_empty() {
                    continue;
                }
                assert!(
                    documented.contains(&format!("/{path}")),
                    "discovery names `{verb} /{path}` — no such operation in the contract"
                );
            }
        }
    }

    /// The behavioral half: every documented operation answers
    /// anything but 405, and every undocumented method on a documented
    /// path answers 405 — on the live router.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_router_serves_the_contract_exactly() {
        let ts = TestServer::spawn(Config::default())
            .await
            .expect("test server");
        for (path, methods) in documented() {
            let concrete = path
                .replace("{id}", "probe-x")
                .replace("{seq}", "1")
                .replace("{gtin}", "09999999999994");
            for verb in VERBS {
                let resp = request(
                    &verb.to_uppercase(),
                    &Url::parse(&format!("{}{concrete}", ts.base_url)).expect("probe url"),
                    &[],
                    if verb == "get" {
                        None
                    } else {
                        Some(b"{}".as_slice())
                    },
                    Duration::from_secs(5),
                )
                .await
                .expect("probe answered");
                if methods.contains(&verb.to_string()) {
                    assert_ne!(
                        resp.status, 405,
                        "{verb} {concrete}: the contract says routed, the router says otherwise"
                    );
                } else {
                    assert_eq!(
                        resp.status, 405,
                        "{verb} {concrete}: served but not in the contract"
                    );
                }
            }
        }
        ts.stop().await;
    }
}
