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
//! | `GET /untp/product/{id}` | the UNTP verifiable-credential triad (passport VC + conformity credentials + link-resolver entry) with the py-adapter verdict |
//! | `GET /en18222/v1/dppsByProductId/{gtin}?representation=full\|compressed` | the EN 18222 REST render (default compressed, per the EN) |
//! | `GET /healthz` | liveness |
//! | `GET /` | discovery: both bindings documented as C4 protocol renderings |

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
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
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8094".parse().expect("static bind"),
            issuer_url: None,
            timeout: Duration::from_secs(2),
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
}

impl AppState {
    /// Assemble state from a config.
    pub fn new(config: Config) -> AppState {
        AppState {
            source: PassportSource::new(config.issuer_url.clone()),
            config,
        }
    }
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
        "description": "UniDPP interop gateway: renders the neutral core in foreign protocol shapes — \
                        their format is our profile (TODO.impl item 27 / PLAN-COMPETE play 2). The py \
                        adapters are the semantics source; this service ports them and serves both \
                        renderings from one core.",
        "endpoints": {
            "untp": "GET /untp/product/{id}?freshness=",
            "en18222": "GET /en18222/v1/dppsByProductId/{gtin}?representation=full|compressed",
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
            "the gateway renders; it never mints",
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
    let Some(passport) = app.source.resolve(&id).await else {
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

// ---------------------------------------------------------------------------
// Route wiring
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/untp/product/{id}", get(untp_product))
        .route("/en18222/v1/dppsByProductId/{gtin}", get(en18222_dpps))
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
