# @floegence/redevplugin-contracts

This opt-in package provides typed, domain-separated canonical release-signing
DTOs, preimage builders, strict decoders, browser-compatible Ed25519 verifier
adapters, and verified presentation-evidence types.

Canonical machine contracts ship as exact artifacts named by the signed
`PlatformReleaseManifest`; this npm package does not embed a second registry or
package-set index. Host products choose their own trusted keys and policy. This
package owns only host-neutral canonicalization, verification request shapes,
and presentation evidence.

## Security summary evidence

Use `normalizeSecuritySummary(value)` to validate verifier output and return a
detached `ExternalPackageSecuritySummary` in canonical field order. Types and
validation descriptors are generated from the platform OpenAPI schema. Unknown
fields, missing required collections, null collections, invalid enum values,
ill-formed Unicode, and non-safe integers are rejected without coercion. Array
order is preserved, and optional absent properties stay absent.

`canonicalSecuritySummaryJSON(value)` encodes all declarations except
`summary_sha256`, including present process and background declarations.
`securitySummarySHA256(value)` and `capabilityContractSetSHA256(value)` use Web
Crypto and match the Go release projection's compact, HTML-safe JSON bytes.
Compare the calculated digest to the claimed digest explicitly; normalization
does not establish package trust, installation authority, or permission grants.
Markets and hosts should consume these APIs rather than keep their own field
allowlists, summary DTOs, or hash payload builders.
