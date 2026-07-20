// Package releasecontract defines the host-neutral canonical wire and signing
// preimages for plugin release trust documents. It does not select trusted keys
// or read the system clock; callers provide timestamps, signatures, and the
// verifier that enforces their source policy.
package releasecontract
