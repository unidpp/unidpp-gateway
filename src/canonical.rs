//! Canonical serialization + digests — a port of
//! `unidpp-py/unidpp/canonical.py` (itself the mirror of `@unidpp/model`
//! `canonical.ts`, I4 commitment hashing / S6 salt discipline).
//!
//! Canonical JSON is "RFC 8785-lite", exactly as in the py/TS
//! references: sorted keys, no whitespace, strings emitted as JSON
//! strings (non-ASCII kept raw), numbers via their shortest round-trip
//! form, non-finite numbers rejected. Over `serde_json::Value` this is
//! `serde_json::to_string`: the default `Map` is a `BTreeMap` (sorted
//! keys), the compact form has no whitespace, and the corpus the
//! gateway round-trips (UNTP stubs: strings, integers, booleans,
//! arrays, objects) serializes byte-identically to the py
//! implementation. Floats and the full ES6/JCS number grammar are
//! intentionally out of scope for the same reason the py core excludes
//! them (see the deviation note in `canonical.py`).
//!
//! The salted commitment mirrors `canonical.py::commitment`:
//! `sha256_hex(salt + ":" + canonical_json(value))`.

use serde_json::Value;

/// RFC 8785-lite canonical JSON: sorted keys, no whitespace.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serde_json serialization of Value cannot fail")
}

/// SHA-256 digest as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    unidpp_model::sha256(&[data]).hex()
}

/// Commitment over canonical JSON with a salt (S6 salt discipline).
pub fn commitment(value: &Value, salt: &str) -> String {
    let material = format!("{salt}:{}", canonical_json(value));
    sha256_hex(material.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_form_sorts_keys_and_strips_whitespace() {
        let v = json!({"b": 1, "a": ["x", 2], "c": {"z": true, "y": null}});
        assert_eq!(
            canonical_json(&v),
            r#"{"a":["x",2],"b":1,"c":{"y":null,"z":true}}"#
        );
    }

    #[test]
    fn commitment_matches_the_py_formula() {
        // sha256("untp-import:" + canonical) — recomputable with:
        //   python3 -c "import hashlib;print(hashlib.sha256(
        //     b'untp-import:{\"a\":1}').hexdigest())"
        let v = json!({"a": 1});
        assert_eq!(
            commitment(&v, "untp-import"),
            sha256_hex(b"untp-import:{\"a\":1}")
        );
        assert_eq!(commitment(&v, "untp-import").len(), 64);
    }

    #[test]
    fn commitments_differ_under_different_salts() {
        let v = json!({"subject": "urn:x"});
        assert_ne!(commitment(&v, "a"), commitment(&v, "b"));
    }
}
