# Author candidate handoff

The `pkg/authorcandidate` package is the host-neutral boundary for an
authoring workspace that wants to offer preview and one-click installation.
The host stores the project and Flower conversation identity, while the
platform binds the reviewed candidate to its exact source digest, package
digest, generation, owner scope, and expiration time.

Hosts should construct an `AuthorCandidateInspection` after a successful
author pipeline build and show its fields in the review UI. The Install action
must send an `AuthorCandidateInstallRequest` containing the same values. A
changed source, package, generation, owner, or expired candidate is rejected;
the host must retain the project and ask the authoring workflow to produce a
new candidate. This keeps a draft or preview from silently becoming a
different installed package.

The contract deliberately does not contain Flower, Redeven, thread, or UI
types. A product may map its creation-project ID and Flower thread ID to the
host-owned project record without making those concepts part of the reusable
plugin platform.
