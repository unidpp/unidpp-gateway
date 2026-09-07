# unidpp-gateway

Part of UniDPP (github.com/unidpp) — `TODO.impl` item 27
(`10-remaining-tasks-definitive.md`, dispatchable C2): the running
**interop gateway** — "their format is our profile" as a service
(PLAN-COMPETE play 2). License: Apache-2.0.

The gateway renders the neutral core in foreign protocol shapes. Both
bindings are **C4 protocol renderings**: a protocol binding is a
registered, versioned render profile over one neutral core — adding a
protocol adds a render profile, never a fork of the core. The py
adapters (`unidpp-py`) are the semantics source; this service ports
them into a running Rust + axum deployment (the org's service stack:
`unidpp-issuer`, `unidpp-registry`, `unidpp-resolver`, `unidpp-gate`).

## Endpoints

| Endpoint | Meaning |
|---|---|
| `GET /untp/product/{id}?freshness=` | the **UNTP verifiable-credential triad**: DigitalProductPassport VC + DigitalConformityCredentials + link-resolver entry, with the py-adapter verdict |
| `GET /en18222/v1/dppsByProductId/{gtin}?representation=full\|compressed` | the **EN 18222 REST render** of the same core (default compressed, per the EN) |
| `GET /healthz` | liveness |
| `GET /` | discovery: both bindings documented as C4 renderings |

### UNTP binding (`urn:unidpp:profile:render:untp`)

A port of `unidpp-py/unidpp/adapters/untp.py` in **both** directions:

- **Render** (`GET /untp/product/{id}`): the passport as a triad —
  1. `passport`: the DigitalProductPassport VC in exactly the py stub
     shape (`@context`, `type`, `id`, `issuer`, `validFrom`/`validUntil`,
     `productIdentifiers`, `passportIssuer`, `standardsConformance`),
     so any UNTP stub consumer parses it;
  2. `conformity`: one DigitalConformityCredential per bound profile
     plus one per E14 `inspection.stamp` in the log (third-party
     assessment level for attested stamps);
  3. `link`: the link-resolver entry (DLR shape: `linkType`/`target`
     plus the log-head anchor).
- **Verdict**: the `verify.py` rule ladder (ported; see below) runs
  over the evidence and ships inside the response.
- **Identifier mapping** (the py `_SCHEME_MAP` and inverse): core
  `cpid` ↔ `https://unidpp.org/id/` (the py `iso-15459` token); the
  GS1 family ↔ `https://gs1.org/voc/`, values in the UNTP
  parenthesized application-identifier form `(01)…(10)…(21)…`.
- **Import** (`unidpp_gateway::untp::parse_stub`): the faithful port
  of py `parse_untp_stub` — scheme mapping, identifier extraction,
  issuer/validity reads, `standardsConformance` → profile bindings,
  the commitment-anchored import receipt
  (`sha256(salt:canonical_json(stub))`, the `canonical.py` port).
  The gateway keeps it so the render → re-parse round-trip is proven
  in the tests.

### EN 18222 binding (`urn:unidpp:profile:render:en18222`)

`GET /en18222/v1/dppsByProductId/{gtin}?representation=full|compressed`
serves the passport in the EN 18222 / EN 18223 JSON shape — the wire
field set mirrored exactly from the freeDPP live-endpoint artifacts
captured in
`unidpp-py/conformance/competitors/freedpp/artifacts/*-api-{full,compressed}.json`
(the reference C# models `FreeDppDppFull.cs`/`FreeDppDppCompressed.cs`):

- the shared header (`digitalProductPassportId`,
  `uniqueProductIdentifier`, `granularity`, `dppSchemaVersion`,
  `dppStatus`, `lastUpdated`, `economicOperatorId`, `facilityId`,
  `contentSpecificationIds`);
- **full**: the `elements` tree of `DataElementCollection`s of
  `SingleValuedDataElement`s, every value string-printed (booleans
  included), `lastUpdated` to the second;
- **compressed** (the EN default): the collections keyed directly,
  native JSON values (`true`, not `"true"`), `lastUpdated` in the
  .NET `"o"` form with a 7-digit fraction — the serialization
  asymmetry the competitor-conformance register documents.

A compatibility render of OUR core: dictionary references mint under
`https://unidpp.org/dp/`; `contentSpecificationIds` carries
`EN 18223:2026` plus the bound profiles. This proves a UniDPP
deployment serves freeDPP-style requests.

### The verdict rules (the `verify.py` port)

`unidpp_gateway::verdict` ports the py verification pipeline
(`unidpp-py/unidpp/verify.py`, I13 degradation ladder + I9 verdicts):
schema leg, taint (fails under every reading), validity window
(`validity-window`), freshness (`assess_freshness` +
`outcome_for_freshness`: stale ⇒ degraded, unknown ⇒ informational),
recall-stale fails outright, and the signature framings over the
document's recorded event signatures — slot lookup
(`suite-unsupported` warning ⇒ degraded), anchor lookup
(`key-unanchored` error ⇒ fail), real verification
(`signature-invalid` on failure), the marker ladder with the py
`testmac`-in-suite ⇒ `self-declared` rule, minimum-marker coverage,
and the py `CoverageReport`/`Verdict` wire shapes.

Deviations from the py original (documented in the module):

- the evidence is the `unidpp/passport@1` document, not a Tier-A pack
  (the gateway renders full passports; the schema leg is held by the
  typed core);
- the py `HmacSha256Slot` test slot is not ported; instead a **real
  Ed25519 slot** (`unidpp-signatif`) is registered — the suite the
  issuer signs events with — with the py `EcdsaNoneSlot` placeholder
  intact (unsupported ⇒ degrade, never fake);
- the py marker token `third-party-attested` maps to/from the Rust
  core's `attested`.

## Data source

Upstream-when-reachable, seeded fixtures otherwise (the
`unidpp-gate` doctrine). Every response carries a `source` marker
(`fixture` | `issuer`):

- **Issuer mode** (`UNIDPP_ISSUER_URL` set and reachable): the gateway
  fetches `GET {issuer}/passports/{id}` (the CLI-compatible document
  view; its `config` vector supplies the profile set) and
  `GET {issuer}/keyring` — so the UNTP render's verdict leg
  **verifies the issuer's real Ed25519 event signatures** against the
  anchors a verifier would pin.
- **Fixtures**: minted with `unidpp-cli`'s own machinery (`Passport::mint`
  + `TypedEvent` appends — what `unidpp create`/`unidpp event` produce):
  - the **laptop** pilot fixture (EU ESPR electronics + JP METI PSE on
    one neutral core; custody transfer, firmware update, part replace);
  - the **tyre** fixture (E8 `consumable.replace` + E14
    `inspection.stamp` under a GTIN identity — the key the EN 18222
    route addresses).

Known limitation: the issuer's store keys passports by passport id,
so a bare GTIN on the EN 18222 route resolves only through the
fixture registry (or an issuer-side index, when one exists).

## Conventions

- as-of stamped responses (`x-as-of` header; `as_of` body member —
  except the EN 18222 render, whose wire field set is frozen to the
  artifact shape; there the stamp rides the header only);
- no-information 404s: identical bytes for unknown and deliberately
  unresolvable ids (I12);
- the gateway renders; it never mints.

## Configuration (`UNIDPP_GATEWAY_*` / `UNIDPP_ISSUER_URL`)

```
UNIDPP_GATEWAY_BIND      # default 127.0.0.1:8094
UNIDPP_ISSUER_URL        # optional; issuer upstream (alias UNIDPP_GATEWAY_ISSUER_URL)
UNIDPP_GATEWAY_TIMEOUT_MS # upstream timeout, default 2000
```

## Build & test

```
cargo build            # zero warnings
cargo test             # 43 unit + 15 integration tests, zero warnings
cargo clippy --all-targets -- -D warnings   # clean
cargo fmt --check      # clean
```

Unit tests cover the canonical-commitment port (byte-identical to the
py formula), the verdict ladder (marker order, outcome combination,
duration grammar, freshness matrix, validity window, taint,
unanchored/unsupported/tampered signature legs, minimum marker, real
Ed25519 verify + tamper detection, the py wire shape), the UNTP
scheme mapping and round-trip (render → `parse_stub`, including the
py passport-mint slug rule), the EN 18222 representations (field
sets, native typing, full/compressed leaf agreement, purity over the
as-of instant), and the source (fixture matching, config-vector
parsing, URL hygiene).

Integration tests speak real HTTP against servers spawned on
ephemeral ports (and one real `unidpp-issuer` instance for the live
upstream): discovery/health, the triad shape against the py stub
expectations, the freshness rule over HTTP, the EN 18222 field sets
against the artifact key sets, both round-trips, the no-information
404, issuer mode with live anchor verification, and the
unreachable-issuer fixture fallback.
