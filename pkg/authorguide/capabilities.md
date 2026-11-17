# Capability authoring

A capability binding selects one exact published contract. It does not declare
callable methods, grant permissions, or prove that the current host registers an
adapter. Declare each required method separately in the source manifest's
`methods` array, with its capability binding and exact target method. SDK imports
do not modify that manifest. An empty `methods` array can be a valid package but
cannot call capability methods.

Use the host's current capability inspection to distinguish:

- contract availability and adapter registration;
- method declaration;
- required and missing grants for declared methods;
- persisted security policy and current host policy;
- mandatory confirmation;
- actual adapter, model and business execution evidence.

An undeclared method needs a source change and build. A missing grant needs the
user's review for the exact instance. A denied policy is not missing consent.
None of these states authorizes replaying an uncertain effect. An inspection
with no admission blockers is not a successful execution or model health check.

Preview and installed instances have independent identities, grants, resources
and conversations. Read the selected preview artifact and instance; do not
substitute the newest build or the installed copy. Hosts own navigation and
review UI. Use their exact-instance settings action rather than inventing a
product menu path. Query failures are unknown state, not empty grants.

Build/package checks, install eligibility, preview admission and business
verification are distinct evidence. Report only checks actually performed.
Exercise first use with no grants, refusal, explicit authorization, configured
operation, revocation and reopen through the actual host boundary. Deterministic
providers can verify integration; they do not establish real-model quality.

The host may expose `Host.InspectPluginCapabilities` through trusted author tools.
It is read-only, returns current facts and never invokes capability adapters or
grants permissions. Its generated declaration examples describe the contract;
authors choose the methods needed by their application.
