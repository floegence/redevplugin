# @floegence/redevplugin-contracts

Host-neutral repository-index, author presentation, and capability-summary
contracts for ordinary ReDevPlugin packages. Plugin publication requires no
signature, trust registry, registration, or review service. Markets and hosts
share these validators rather than maintain independent package definitions.

Canonical contracts ship in the platform release artifact set. Platform release
integrity and runtime lease verification remain independent of plugin admission.

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
does not establish installation authority, or permission grants.
Markets and hosts should consume these APIs rather than keep their own field
allowlists, summary DTOs, or hash payload builders.

`securitySummaryJSONSchema` exposes the same generated contract as a standalone
JSON Schema 2020-12 document with local definitions. Use it to generate a
downstream schema file or validate transport evidence without copying field
definitions. Treat the exported schema as immutable.
