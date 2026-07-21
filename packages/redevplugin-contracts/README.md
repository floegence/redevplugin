# @floegence/redevplugin-contracts

This opt-in package exposes the immutable ReDevPlugin machine-contract registry,
contract bodies, hashes, and platform package set. It also provides typed,
domain-separated canonical release-signing DTOs, preimage builders, strict
decoders, detached signing-ledger evidence DTOs, and browser-compatible
verifier adapters.

Ordinary ReDevPlugin UI imports do not load the raw contract bodies. Host
products choose their own trusted keys and policy; this package owns only the
host-neutral wire, canonicalization, and signature-verification request shape.
