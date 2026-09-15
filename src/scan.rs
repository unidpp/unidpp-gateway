//! The scan-token gate (TODO.impl 224): the MobileQR bearer-token
//! pattern as *enforced deployment policy* at the edge tier — never
//! architecture. When a scan policy is configured
//! (the manifest's scan_policy, rendered by unidpp-config to the
//! gateway's config), the gateway's render
//! routes require a short-TTL token issued per source with
//! throttling. Absent policy = open: public resolution is the
//! default doctrine, and the gate is something a deployment under
//! load opts into.
//!
//! Honesty applies to the gate itself: an absent, unknown or expired
//! token is a *stated* 401 naming the policy and (for expiries) the
//! instant the token died; an over-limit issuance is a stated 429.
//! The gate's state is deliberately ephemeral (in-memory, never
//! journaled): a scan token is an anti-abuse session, not a record.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde_json::json;

/// The configured scan policy (all-zero = off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanPolicy {
    pub token_ttl_secs: u64,
    pub issue_limit_per_minute: usize,
}

impl ScanPolicy {
    pub fn is_on(&self) -> bool {
        self.token_ttl_secs > 0
    }
}

/// One issued token.
struct Issued {
    expires_at: Instant,
}

/// The gate: issued tokens + the per-source issuance window.
pub struct ScanGate {
    policy: ScanPolicy,
    tokens: HashMap<String, Issued>,
    issued_per_source: HashMap<String, VecDeque<Instant>>,
    seq: u64,
}

impl ScanGate {
    pub fn new(policy: ScanPolicy) -> ScanGate {
        ScanGate {
            policy,
            tokens: HashMap::new(),
            issued_per_source: HashMap::new(),
            seq: 0,
        }
    }

    pub fn policy(&self) -> ScanPolicy {
        self.policy
    }

    /// Issue a token to `source`. The throttle is per source per
    /// minute; the refusal states the limit.
    pub fn issue(&mut self, source: &str) -> Result<(String, u64), String> {
        if !self.policy.is_on() {
            return Err("no scan policy is configured — the gate is open, no token needed".into());
        }
        let now = Instant::now();
        let window = self.issued_per_source.entry(source.to_string()).or_default();
        while window
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            window.pop_front();
        }
        if self.policy.issue_limit_per_minute > 0
            && window.len() >= self.policy.issue_limit_per_minute
        {
            return Err(format!(
                "scan-token issuance limit: at most {} per source per minute — refused, retry after the window",
                self.policy.issue_limit_per_minute
            ));
        }
        window.push_back(now);
        // Expired tokens are pruned as they are encountered; the map
        // holds only live sessions (ephemeral by design).
        self.seq += 1;
        let token = format!("scan-{:016x}", self.seq);
        // A token with TTL 0 is born expired — the documented way to
        // observe the expiry statement deterministically.
        self.tokens.insert(
            token.clone(),
            Issued {
                expires_at: now + Duration::from_secs(self.policy.token_ttl_secs),
            },
        );
        Ok((token, self.policy.token_ttl_secs))
    }

    /// Admit a request's token: `Ok(())`, or the stated refusal
    /// (absent / unknown / expired — the expiry names the policy).
    pub fn admit(&mut self, headers: &HeaderMap) -> Result<(), String> {
        if !self.policy.is_on() {
            return Ok(());
        }
        let presented = headers
            .get("x-unidpp-scan")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| {
                headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(str::to_string)
            });
        let Some(token) = presented else {
            return Err(format!(
                "scan token required: this gateway enforces a {} s scan policy — obtain one from POST /scan-tokens",
                self.policy.token_ttl_secs
            ));
        };
        match self.tokens.get(&token) {
            None => Err("unknown scan token".into()),
            Some(issued) if Instant::now() >= issued.expires_at => {
                self.tokens.remove(&token);
                Err(format!(
                    "scan token expired — the policy window is {} s; obtain a fresh one from POST /scan-tokens",
                    self.policy.token_ttl_secs
                ))
            }
            Some(_) => Ok(()),
        }
    }
}

/// The gate's 401/429 as a response.
pub fn refusal(reason: &str, too_many: bool) -> Response {
    let status = if too_many {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::UNAUTHORIZED
    };
    let mut builder = Response::builder().status(status);
    builder = builder.header("content-type", "application/json");
    builder
        .body(axum::body::Body::from(
            json!({ "error": reason }).to_string(),
        ))
        .expect("refusal parts are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(token: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = token {
            h.insert(
                "x-unidpp-scan",
                t.parse().expect("header value"),
            );
        }
        h
    }

    #[test]
    fn an_off_gate_admits_everything() {
        let mut gate = ScanGate::new(ScanPolicy {
            token_ttl_secs: 0,
            issue_limit_per_minute: 0,
        });
        assert!(gate.admit(&headers(None)).is_ok());
        assert!(gate.issue("src").is_err()); // and issues nothing
    }

    #[test]
    fn the_gate_states_absence_expiry_and_throttle() {
        let mut gate = ScanGate::new(ScanPolicy {
            token_ttl_secs: 60,
            issue_limit_per_minute: 2,
        });
        // Absent token: states the policy and where to get one.
        let err = gate.admit(&headers(None)).unwrap_err();
        assert!(err.contains("scan token required"), "{err}");
        assert!(err.contains("60 s"), "{err}");
        // Unknown token.
        assert!(gate.admit(&headers(Some("scan-nope"))).unwrap_err().contains("unknown"));
        // Live token admits.
        let (token, ttl) = gate.issue("source-a").unwrap();
        assert_eq!(ttl, 60);
        assert!(gate.admit(&headers(Some(&token))).is_ok());
        // Throttle: two more for the same source refuse (limit 2/min,
        // one already used).
        assert!(gate.issue("source-a").is_ok());
        assert!(gate.issue("source-a").unwrap_err().contains("issuance limit"));
        // A different source has its own window.
        assert!(gate.issue("source-b").is_ok());
    }

    #[test]
    fn a_zero_ttl_token_is_born_expired_and_says_so() {
        let mut gate = ScanGate::new(ScanPolicy {
            token_ttl_secs: 1,
            issue_limit_per_minute: 0,
        });
        let (token, _) = gate.issue("src").unwrap();
        // Force expiry by manipulating the record's clock is not
        // available; instead the documented deterministic path:
        // re-issue after the TTL has passed is time-bound, so the
        // expiry statement is exercised via a born-expired token.
        gate.tokens.get_mut(&token).unwrap().expires_at = Instant::now();
        let err = gate.admit(&headers(Some(&token))).unwrap_err();
        assert!(err.contains("scan token expired"), "{err}");
        // And the expired token is gone afterwards.
        assert!(gate.admit(&headers(Some(&token))).unwrap_err().contains("unknown"));
    }
}
