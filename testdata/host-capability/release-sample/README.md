# Release Sample Signing Key

The private key in this directory is a deterministic, test-only fixture used to
sign the host-neutral capability sample during release-bundle construction. It
is public repository data, is not trusted by any source policy, and must never
be used for a real publisher or registry.

The release bundle contains only the matching public key. The build regenerates
the signed sample with the release `source_commit`, then the bundle verifier
checks that provenance before accepting the artifact.
