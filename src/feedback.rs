//! The consumer report channel (TODO.impl 224): MobileQR's 投诉反馈
//! pattern — a *stated* report path on the public edge. A consumer
//! who finds the goods or the advertising not matching the page files
//! a typed report; the report is journaled (append-only JSONL, the
//! house pattern), sequenced, and acknowledged with a receipt naming
//! its sequence and instant. The report is information *about* an
//! identifier from a weakly-authenticated party — never a passport
//! event (the consumer is not an event actor on the EO's log); it
//! lives here, at the gateway, the public edge tier.
//!
//! Admission control is pluggable ([`AdmissionControl`]) and never
//! architecture: MobileQR's phone + Aliyun captcha + SMS is one
//! deployment's choice; a rate window ([`RateLimited`]) is another;
//! [`Permissive`] is the default for dev. Whatever refuses, refuses
//! with a stated reason.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The report's category — MobileQR's two structured complaint types
/// (实物与本页面不符 / 宣传与本页面不符) plus a stated free-form other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedbackCategory {
    GoodsMismatch,
    AdvertisingMismatch,
    Other(String),
}

impl FeedbackCategory {
    pub fn parse(s: &str) -> FeedbackCategory {
        match s.trim() {
            "goods-mismatch" => FeedbackCategory::GoodsMismatch,
            "advertising-mismatch" => FeedbackCategory::AdvertisingMismatch,
            other => FeedbackCategory::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            FeedbackCategory::GoodsMismatch => "goods-mismatch".into(),
            FeedbackCategory::AdvertisingMismatch => "advertising-mismatch".into(),
            FeedbackCategory::Other(free) => format!("other:{free}"),
        }
    }
}

/// One consumer report: what it is about (the identifier), the typed
/// category, optional contact, and the details. MobileQR caps the
/// description at 100 characters; the gateway caps at 500 — the cap
/// is stated in the refusal either way.
#[derive(Debug, Clone)]
pub struct FeedbackReport {
    pub identifier: String,
    pub category: FeedbackCategory,
    pub contact: Option<String>,
    pub details: String,
}

/// A journaled report with its sequence and instant.
#[derive(Debug, Clone)]
pub struct FeedbackRecord {
    pub seq: u64,
    pub recorded_at: String,
    pub report: FeedbackReport,
}

impl FeedbackRecord {
    pub fn to_json(&self, include_contact: bool) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("seq".into(), json!(self.seq));
        m.insert("recorded_at".into(), json!(self.recorded_at));
        m.insert("identifier".into(), json!(self.report.identifier));
        m.insert("category".into(), json!(self.report.category.as_str()));
        m.insert("details".into(), json!(self.report.details));
        if include_contact {
            m.insert("contact".into(), json!(self.report.contact));
        } else {
            // The omission is stated, never silent (the public form
            // exists so a report can be cited by sequence without
            // exposing the reporter).
            m.insert("contact".into(), json!("withheld"));
        }
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Result<FeedbackRecord, String> {
        let obj = v.as_object().ok_or("feedback record must be an object")?;
        Ok(FeedbackRecord {
            seq: obj.get("seq").and_then(Value::as_u64).ok_or("missing `seq`")?,
            recorded_at: obj
                .get("recorded_at")
                .and_then(Value::as_str)
                .ok_or("missing `recorded_at`")?
                .to_string(),
            report: FeedbackReport {
                identifier: obj
                    .get("identifier")
                    .and_then(Value::as_str)
                    .ok_or("missing `identifier`")?
                    .to_string(),
                category: FeedbackCategory::parse(
                    obj.get("category").and_then(Value::as_str).unwrap_or(""),
                ),
                contact: obj
                    .get("contact")
                    .and_then(Value::as_str)
                    .filter(|c| !c.is_empty())
                    .map(str::to_string),
                details: obj
                    .get("details")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            },
        })
    }
}

/// The report journal: in-memory records + optional JSONL persistence
/// (replayed on open — the registry/trust/resolver storage pattern).
pub struct FeedbackStore {
    records: Vec<FeedbackRecord>,
    journal: Option<File>,
}

impl FeedbackStore {
    pub fn open(journal: Option<&Path>) -> std::io::Result<FeedbackStore> {
        let mut store = FeedbackStore {
            records: Vec::new(),
            journal: None,
        };
        if let Some(path) = journal {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if path.exists() {
                let file = File::open(path)?;
                for (i, line) in BufReader::new(file).lines().enumerate() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<Value>(&line)
                        .map_err(|e| e.to_string())
                        .and_then(|v| FeedbackRecord::from_json(&v))
                    {
                        Ok(rec) => store.records.push(rec),
                        Err(e) => {
                            // A torn final line (crash mid-write) is
                            // tolerated; anything else is loud.
                            eprintln!("unidpp-gateway: feedback journal line {}: {e}", i + 1);
                        }
                    }
                }
            }
            store.journal = Some(OpenOptions::new().create(true).append(true).open(path)?);
        }
        Ok(store)
    }

    /// Validate and journal a report; the receipt is the record.
    pub fn submit(&mut self, report: FeedbackReport, now: &str) -> Result<FeedbackRecord, String> {
        if report.identifier.trim().is_empty() {
            return Err("`identifier` is required — a report is about something".into());
        }
        if report.details.trim().is_empty() {
            return Err("`details` is required — a report states what did not match".into());
        }
        if report.details.chars().count() > 500 {
            return Err("`details` exceeds 500 characters".into());
        }
        let rec = FeedbackRecord {
            seq: self.records.len() as u64 + 1,
            recorded_at: now.to_string(),
            report,
        };
        if let Some(j) = self.journal.as_mut() {
            if let Err(e) = writeln!(j, "{}", rec.to_json(true)) {
                eprintln!("unidpp-gateway: feedback journal write failed: {e}");
            }
        }
        self.records.push(rec.clone());
        Ok(rec)
    }

    /// The public citation form: by sequence, contact withheld.
    pub fn get(&self, seq: u64) -> Option<Value> {
        self.records
            .get(seq.checked_sub(1)? as usize)
            .map(|r| r.to_json(false))
    }

    /// The admin listing: contacts included, newest first.
    pub fn list_json(&self, limit: usize, offset: usize) -> Value {
        let total = self.records.len();
        let slice: Vec<Value> = self
            .records
            .iter()
            .rev()
            .skip(offset)
            .take(limit)
            .map(|r| r.to_json(true))
            .collect();
        json!({ "total": total, "offset": offset, "records": slice })
    }
}

/// Admission control: the pluggable gate a deployment puts in front
/// of the report path. Implementations refuse with a *stated* reason.
/// MobileQR's captcha + SMS verification is one such implementation
/// (needing external services); the in-repo [`RateLimited`] is
/// another; [`Permissive`] is the dev default. The architecture
/// demands only this trait — never any particular mechanism.
pub trait AdmissionControl: Send + Sync {
    fn admit(&self, report: &FeedbackReport) -> Result<(), String>;
}

/// The dev default: everything stated is admitted.
pub struct Permissive;

impl AdmissionControl for Permissive {
    fn admit(&self, _report: &FeedbackReport) -> Result<(), String> {
        Ok(())
    }
}

/// A per-identifier sliding window: at most `limit` reports per
/// identifier per `window` — the flood shape abuse control exists to
/// stop, without surveilling anyone.
pub struct RateLimited {
    limit: usize,
    window: Duration,
    seen: std::sync::Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimited {
    pub fn per_minute(limit: usize) -> RateLimited {
        RateLimited {
            limit,
            window: Duration::from_secs(60),
            seen: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

impl AdmissionControl for RateLimited {
    fn admit(&self, report: &FeedbackReport) -> Result<(), String> {
        let now = Instant::now();
        let mut seen = self.seen.lock().expect("rate window poisoned");
        let window = seen.entry(report.identifier.clone()).or_default();
        while window.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            window.pop_front();
        }
        if window.len() >= self.limit {
            return Err(format!(
                "rate limit: at most {} report(s) per identifier per minute — refused, retry after the window",
                self.limit
            ));
        }
        window.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(identifier: &str) -> FeedbackReport {
        FeedbackReport {
            identifier: identifier.into(),
            category: FeedbackCategory::GoodsMismatch,
            contact: Some("reporter@example.org".into()),
            details: "the package says 20 Ah, the page says 0.072 kWh".into(),
        }
    }

    #[test]
    fn submission_receipts_and_the_public_form_withholds_contact() {
        let mut store = FeedbackStore::open(None).unwrap();
        let rec = store
            .submit(report("gs1:(01)06901234567892"), "2026-09-15T12:00:00Z")
            .unwrap();
        assert_eq!(rec.seq, 1);
        let public = store.get(1).unwrap();
        assert_eq!(public["contact"], json!("withheld"));
        assert_eq!(public["category"], json!("goods-mismatch"));
        let admin = store.list_json(10, 0);
        assert_eq!(admin["records"][0]["contact"], json!("reporter@example.org"));
        // Validation refuses the unstated.
        assert!(store
            .submit(
                FeedbackReport {
                    identifier: " ".into(),
                    category: FeedbackCategory::GoodsMismatch,
                    contact: None,
                    details: "x".into()
                },
                "2026-09-15T12:00:01Z"
            )
            .is_err());
    }

    #[test]
    fn the_rate_window_refuses_with_a_stated_reason() {
        let gate = RateLimited::per_minute(2);
        let r = report("gs1:(01)06901234567892");
        assert!(gate.admit(&r).is_ok());
        assert!(gate.admit(&r).is_ok());
        let refusal = gate.admit(&r).unwrap_err();
        assert!(refusal.contains("rate limit"), "{refusal}");
        // A different identifier is a different window.
        assert!(gate.admit(&report("gs1:(01)09506000134352")).is_ok());
    }

    #[test]
    fn the_journal_replays() {
        let dir = std::env::temp_dir().join(format!("unidpp-gw-fb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("feedback.jsonl");
        let _ = std::fs::remove_file(&path);
        {
            let mut store = FeedbackStore::open(Some(&path)).unwrap();
            store
                .submit(report("gs1:(01)06901234567892"), "2026-09-15T12:00:00Z")
                .unwrap();
            store
                .submit(
                    FeedbackReport {
                        identifier: "gs1:(01)06901234567892".into(),
                        category: FeedbackCategory::AdvertisingMismatch,
                        contact: None,
                        details: "the ad claims Qi2, the page does not".into(),
                    },
                    "2026-09-15T12:05:00Z",
                )
                .unwrap();
        }
        let replayed = FeedbackStore::open(Some(&path)).unwrap();
        assert_eq!(replayed.list_json(10, 0)["total"], json!(2));
        assert_eq!(
            replayed.get(2).unwrap()["category"],
            json!("advertising-mismatch")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
