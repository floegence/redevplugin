# redevplugin-contracts

`redevplugin-contracts` embeds the versioned machine contracts published by the
ReDevPlugin platform. It exposes validated contract IDs, immutable canonical
bytes, hashes, registry metadata, and the platform package set.

The crate is opt-in. The runtime and ordinary Host dependency graphs use only
the generated contract-set digest and do not link the raw contract bodies.
