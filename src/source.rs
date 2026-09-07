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
}

impl PassportSource {
    /// Assemble the source: the seeded fixtures plus an optional
    /// issuer upstream base URL (`http://host:port`, no trailing path).
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
        let base = self.issuer_url.as_ref()?;
        let id = Url::encode_query_component(id);
        let response = json_request(
            "GET",
            &format!("{base}/passports/{id}"),
            None,
            None,
            self.timeout,
        )
        .await
        .ok()?;
        if response.status != 200 {
            return None;
        }
        let view: Value = serde_json::from_str(&response.body_string()).ok()?;
        let document = Passport::from_json(&response.body_string()).ok()?;
        let profiles = parse_config_profiles(&view);
        let anchors = self.fetch_anchors(base).await;
        Some(GatewayPassport {
            document,
            profiles,
            origin: Origin::Issuer,
            anchors,
        })
    }

    /// Best-effort keyring fetch: the public anchors a verifier pins.
    /// An unreachable keyring yields no anchors (the verdict's
    /// `key-unanchored` rule then fails loudly — never silently).
    async fn fetch_anchors(&self, base: &str) -> HashMap<String, PublicKeyMaterial> {
        let mut out = HashMap::new();
        let Ok(response) =
            json_request("GET", &format!("{base}/keyring"), None, None, self.timeout).await
        else {
            return out;
        };
        if response.status != 200 {
            return out;
        }
        let Ok(keyring) = serde_json::from_str::<Value>(&response.body_string()) else {
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
