//! The data source: the seeded fixture set, plus the issuer service as
//! upstream-when-reachable (`UNIDPP_ISSUER_URL`) — the `unidpp-gate`
//! doctrine. The gateway renders; it never mints. Every rendered
//! passport carries a `source` marker (`fixture` | `issuer`) so a
//! consumer can see whether the render is live.
//!
//! Issuer mode fetches the `unidpp/passport@1` document from
//! `GET {issuer}/passports/{id}` (the view the issuer serves is
//! CLI-compatible; its `config` vector supplies the profile set) and
//! the public anchors from `GET {issuer}/keyring`, so the UNTP
//! render's verdict leg verifies the issuer's real Ed25519 event
//! signatures against the anchors a verifier would pin.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;
use unidpp_cli::passport::Passport;

use crate::http::{json_request, Url};
use crate::verdict::PublicKeyMaterial;

/// The transport boundary of the gateway→issuer edge (REARCH R7):
/// exactly the two documents the gateway fetches — the passport view
/// and the keyring — as raw JSON bodies. The default implementation
/// is the loopback HTTP client inside [`PassportSource`];
/// [`InProcessIssuer`] is the embedder's bridge, serving both
/// documents from the issuer module's own router in the same process.
/// The outcome of one upstream view fetch: the rendered view body,
/// the pack document, and the trust anchors, or `None` when the
/// issuer does not know the identifier.
pub type FetchedView = Option<(String, String, HashMap<String, PublicKeyMaterial>)>;

pub trait IssuerUpstream: Send + Sync {
    fn fetch_view_and_keyring<'a>(
        &'a self,
        id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FetchedView> + Send + 'a>>;
}

/// Where a rendered passport came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Fixture,
    Issuer,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Fixture => "fixture",
            Origin::Issuer => "issuer",
        }
    }
}

/// A profile bound to the passport (the issuer's config vector, or the
/// fixture's declared lens set): id + version + effective window.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileRef {
    pub id: String,
    pub version: String,
    pub effective_from: Option<unidpp_model::Timestamp>,
}

/// A passport ready to render: the CLI-compatible document plus the
/// profile layer and (issuer mode) the pinned anchors.
#[derive(Debug, Clone)]
pub struct GatewayPassport {
    pub document: Passport,
    pub profiles: Vec<ProfileRef>,
    pub origin: Origin,
    /// Trust anchors by key id (issuer keyring; empty for fixtures,
    /// whose documents carry no event signatures).
    pub anchors: HashMap<String, PublicKeyMaterial>,
}

impl GatewayPassport {
    /// Fixture-backed passport.
    pub fn fixture(document: Passport, profiles: Vec<ProfileRef>) -> GatewayPassport {
        GatewayPassport {
            document,
            profiles,
            origin: Origin::Fixture,
            anchors: HashMap::new(),
        }
    }

    /// The GTIN key when the subject identity is GS1-keyed (what the
    /// EN 18222 `dppsByProductId` route addresses).
    pub fn gtin_key(&self) -> Option<&str> {
        use unidpp_model::IdScheme;
        match self.document.product_id.scheme {
            IdScheme::Gtin | IdScheme::Sgtin => Some(&self.document.product_id.key),
            _ => None,
        }
    }
}

/// The passport data source.
pub struct PassportSource {
    fixtures: Vec<GatewayPassport>,
    issuer_url: Option<String>,
    timeout: Duration,
    /// The in-process issuer bridge (REARCH R7): when set, issuer
    /// lookups ride the trait instead of loopback HTTP.
    issuer_bridge: Option<std::sync::Arc<dyn IssuerUpstream>>,
}

impl PassportSource {
    /// Assemble the source: the seeded fixtures plus an optional
    /// issuer upstream base URL (`http://host:port`, no trailing path).
    /// Swap the issuer transport (REARCH R7): the one deployment
    /// injects the in-process bridge.
    pub fn with_issuer_bridge(mut self, bridge: std::sync::Arc<dyn IssuerUpstream>) -> Self {
        self.issuer_bridge = Some(bridge);
        self
    }

    pub fn new(issuer_url: Option<String>) -> PassportSource {
        let fixtures = crate::fixtures::all()
            .into_iter()
            .map(|(document, profiles)| GatewayPassport::fixture(document, profiles))
            .collect();
        PassportSource {
            fixtures,
            issuer_url: issuer_url
                .map(|u| u.trim().trim_end_matches('/').to_string())
                .filter(|u| !u.is_empty()),
            timeout: Duration::from_secs(2),
            issuer_bridge: None,
        }
    }

    /// The configured issuer base URL, when any.
    pub fn issuer_url(&self) -> Option<&str> {
        self.issuer_url.as_deref()
    }

    /// Fixture index for the discovery document: (passport id, gtin?).
    pub fn fixture_index(&self) -> Vec<Value> {
        self.fixtures
            .iter()
            .map(|p| {
                let mut v = serde_json::json!({
                    "passport_id": p.document.passport_id.as_str(),
                    "product_id": p.document.product_id.to_string(),
                });
                if let Some(gtin) = p.gtin_key() {
                    v["gtin"] = serde_json::json!(gtin);
                }
                v
            })
            .collect()
    }

    fn fixture_match(&self, id: &str) -> Option<&GatewayPassport> {
        self.fixtures.iter().find(|p| {
            p.document.passport_id.as_str() == id
                || p.document.product_id.to_string() == id
                || p.gtin_key() == Some(id)
        })
    }

    /// Resolve by passport id or product identity: fixtures first,
    /// then the issuer upstream (passenger-id keyed).
    pub async fn resolve(&self, id: &str) -> Option<GatewayPassport> {
        if let Some(found) = self.fixture_match(id) {
            return Some(found.clone());
        }
        self.issuer_lookup(id).await
    }

    /// Resolve by GTIN for the EN 18222 route: fixture GS1 keys first,
    /// then the issuer (whose store keys passports by passport id, so
    /// a bare GTIN resolves only when the issuer knows it under that
    /// key — the documented limitation of issuer-mode GTIN lookup).
    pub async fn resolve_gtin(&self, gtin: &str) -> Option<GatewayPassport> {
        if let Some(found) = self.fixtures.iter().find(|p| p.gtin_key() == Some(gtin)) {
            return Some(found.clone());
        }
        self.issuer_lookup(gtin).await
    }

    /// Fetch and parse a passport view from the issuer, plus its
    /// public anchors. Any failure is a miss (the caller 404s
    /// no-information); a configured-but-unreachable issuer degrades to
    /// the fixtures through the earlier fixture match.
    async fn issuer_lookup(&self, id: &str) -> Option<GatewayPassport> {
        let (view_body, document_body, anchors) = match &self.issuer_bridge {
            Some(bridge) => bridge.fetch_view_and_keyring(id).await?,
            None => {
                let base = self.issuer_url.as_ref()?;
                let encoded = Url::encode_query_component(id);
                let response = json_request(
                    "GET",
                    &format!("{base}/passports/{encoded}"),
                    None,
                    None,
                    self.timeout,
                )
                .await
                .ok()?;
                if response.status != 200 {
                    return None;
                }
                let body = response.body_string();
                let keyring_body = self.fetch_keyring_body(base).await;
                (body.clone(), body, keyring_body)
            }
        };
        let view: Value = serde_json::from_str(&view_body).ok()?;
        let document = Passport::from_json(&document_body).ok()?;
        let profiles = parse_config_profiles(&view);
        Some(GatewayPassport {
            document,
            profiles,
            origin: Origin::Issuer,
            anchors,
        })
    }

    /// The keyring body through the bridge, or over HTTP standalone.
    async fn fetch_keyring_body(&self, base: &str) -> HashMap<String, PublicKeyMaterial> {
        Self::parse_keyring_body(
            json_request("GET", &format!("{base}/keyring"), None, None, self.timeout)
                .await
                .map(|r| r.body_string()),
        )
    }

    /// The keyring parse, shared by the HTTP path and the bridge.
    fn parse_keyring_body(body: Result<String, String>) -> HashMap<String, PublicKeyMaterial> {
        let mut out = HashMap::new();
        let Ok(body) = body else {
            return out;
        };
        if body.is_empty() {
            return out;
        }
        let Ok(keyring) = serde_json::from_str::<Value>(&body) else {
            return out;
        };
        let Some(roles) = keyring.get("roles").and_then(Value::as_object) else {
            return out;
        };
        for role in roles.values() {
            let (Some(key_id), Some(public_hex), Some(suite)) = (
                role.get("key_id").and_then(Value::as_str),
                role.get("public").and_then(Value::as_str),
                role.get("suite").and_then(Value::as_str),
            ) else {
                continue;
            };
            if suite != "ed25519" {
                continue; // the slot the gateway's verdict leg registers
            }
            if let Ok(bytes) = unidpp_cli::encoding::hex_decode(public_hex) {
                out.insert(key_id.to_string(), PublicKeyMaterial { bytes });
            }
        }
        out
    }
}

/// The in-process issuer bridge (REARCH R7): the same two GETs the
/// HTTP path makes, served from the issuer module's own router in the
/// same process — no sockets, no URL. The encoding and parsing are
/// this crate's own, so the parity with the HTTP path is by
/// construction.
pub struct InProcessIssuer {
    pub router: axum::Router,
}

impl InProcessIssuer {
    async fn get(&self, path: &str) -> Option<String> {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .body(axum::body::Body::empty())
            .expect("static request parts");
        let response = tower::util::ServiceExt::oneshot(&mut self.router.clone(), request)
            .await
            .expect("the issuer router answers");
        if response.status() != axum::http::StatusCode::OK {
            return None;
        }
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .ok()?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

impl IssuerUpstream for InProcessIssuer {
    fn fetch_view_and_keyring<'a>(
        &'a self,
        id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Option<(String, String, HashMap<String, PublicKeyMaterial>)>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let encoded = Url::encode_query_component(id);
            let view = self.get(&format!("/passports/{encoded}")).await?;
            let keyring = self.get("/keyring").await.unwrap_or_default();
            let anchors = PassportSource::parse_keyring_body(Ok(keyring.clone()));
            Some((view.clone(), view, anchors))
        })
    }
}

/// The issuer view's config vector: profile id strings, optionally
/// `id@version` (a bare id pins version `0`, the py adapter's default).
fn parse_config_profiles(view: &Value) -> Vec<ProfileRef> {
    let Some(entries) = view.get("config").and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| entry.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|entry| match entry.split_once('@') {
            Some((id, version)) => ProfileRef {
                id: id.trim().to_string(),
                version: version.trim().to_string(),
                effective_from: None,
            },
            None => ProfileRef {
                id: entry.trim().to_string(),
                version: "0".to_string(),
                effective_from: None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_resolve_by_passport_id_product_id_and_gtin() {
        let source = PassportSource::new(None);
        let by_passport = source
            .fixture_match("urn:iso:std:iso-iec:15459:unidpp:passport:84120099012345")
            .expect("laptop by passport id");
        assert_eq!(by_passport.origin, Origin::Fixture);
        assert!(source
            .fixture_match("cpid:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345")
            .is_some());
        assert!(source.fixture_match("4006381333931").is_some());
        assert!(source.fixture_match("urn:unidpp:passport:nope").is_none());
    }

    #[test]
    fn config_profiles_split_on_version_pin() {
        let view: Value =
            serde_json::from_str(r#"{"config": ["urn:p:a@1.2.3", "urn:p:b", ""]}"#).unwrap();
        let profiles = parse_config_profiles(&view);
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].id, "urn:p:a");
        assert_eq!(profiles[0].version, "1.2.3");
        assert_eq!(profiles[1].version, "0");
    }

    #[test]
    fn issuer_url_trims_trailing_slashes() {
        let source = PassportSource::new(Some("http://127.0.0.1:8091/".into()));
        assert_eq!(source.issuer_url(), Some("http://127.0.0.1:8091"));
        assert!(PassportSource::new(Some("   ".into()))
            .issuer_url()
            .is_none());
        assert!(PassportSource::new(None).issuer_url().is_none());
    }

    #[test]
    fn fixture_index_lists_both_fixtures() {
        let source = PassportSource::new(None);
        let index = source.fixture_index();
        assert_eq!(index.len(), 2);
        assert!(index.iter().any(|v| v.get("gtin").is_some()));
    }
}
