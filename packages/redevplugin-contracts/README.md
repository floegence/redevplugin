# @floegence/redevplugin-contracts

This opt-in package provides typed, domain-separated canonical release-signing
DTOs, preimage builders, strict decoders, browser-compatible Ed25519 verifier
adapters, and verified presentation-evidence types.

Canonical machine contracts ship as exact artifacts named by the signed
`PlatformReleaseManifest`; this npm package does not embed a second registry or
package-set index. Host products choose their own trusted keys and policy. This
package owns only host-neutral canonicalization, verification request shapes,
and presentation evidence.
