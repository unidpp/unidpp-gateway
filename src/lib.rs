//! The UniDPP interop gateway — "their format is our profile" as a
//! service (TODO.impl item 27 / PLAN-COMPETE play 2, dispatchable C2).
//!
//! Two protocol renderings of one neutral core, both registered as
//! profiles (C4: a protocol binding is a render profile, never a fork
//! of the core):
//!
//! - [`untp`] — the UNTP binding: a port of the py adapter
//!   (`unidpp-py/unidpp/adapters/untp.py`, the semantics source) in
//!   both directions, rendering a passport as a verifiable-credential
//!   triad (passport VC + conformity credentials + link-resolver
//!   entry) with the `verify.py` verdict rules ([`verdict`]) over the
//!   evidence;
//! - [`en18222`] — the EN 18222 REST render
//!   (`/v1/dppsByProductId/{gtin}?representation=full|compressed`),
//!   wire shape mirrored from the freeDPP live-endpoint artifacts: a
//!   compatibility render proving a UniDPP deployment serves
//!   freeDPP-style requests.
//!
//! The data source ([`source`]) is the issuer service when reachable
//! (`UNIDPP_ISSUER_URL`), the seeded CLI fixtures otherwise — the
//! fixtures are minted with `unidpp-cli`'s own machinery (what
//! `unidpp create` / `unidpp event` produce), so the fallback is the
//! real document shape, not a mock.

pub mod api;
pub mod canonical;
pub mod en18222;
pub mod fixtures;
pub mod http;
pub mod ingest;
pub mod source;
pub mod untp;
pub mod verdict;

pub use api::{router, run, AppState, Config, TestServer, NOT_FOUND_BODY};
