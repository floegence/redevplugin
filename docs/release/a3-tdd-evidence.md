# A3 Historical TDD Evidence

This file records historical context for ReDevPlugin v0.3.2. That release used
an independently signed host-capability artifact bundle and separate operation
and stream identities. Those mechanisms are not part of the current platform
contract.

The current platform keeps capability contracts and exact pins in a closed
host-local registry. It has no independent capability publisher, remote
capability admission chain, or durable capability receipt lifecycle. All public
asynchronous work uses one Execution identity with ordered Events and a cursor.

Current source, generated contracts, focused tests, and
`docs/release/ci-and-release-gates.md` are authoritative. Historical commands,
artifact layouts, schema inventories, and test names from v0.3.2 must not be
used as current release or integration guidance.
