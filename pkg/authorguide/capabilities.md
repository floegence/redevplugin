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

For installation, the trusted Host review may offer explicit consent to the
verified `grantable_permissions`. The platform commits the selected grants with
the exact inspected package; installation without that consent grants nothing.
Do not create a second plugin-owned "enable capability" permission switch or
instruct users to install first and search settings for essential access. Keep
application configuration (model choice, object/profile setup and preferences)
separate from Host permission consent. Already installed missing access uses
the Host's exact-instance review. Preview grants never transfer to installation.

## Keep first use accessible

Declare `authorization.scoped.v1` in `api.required_features` to give each surface
an explicit `required_methods` list. These are startup dependencies, not callable
method declarations. Omission keeps aggregate plugin authorization: a missing
grant for any declared method can prevent the entire interface from opening.

A surface that renders its local content and setup controls independently may
use `"required_methods": []`. A surface that must read protected data before it
can render lists those exact methods instead. Every subsequent capability call
still needs its declaration, permissions, policy admission and confirmation.
Do not set an empty list just to suppress a failure: first make initialization
tolerate unavailable capabilities and preserve local content and setup controls.

Hosts read `getPluginSurfaceActionState(record, surfaceId)` from the current
catalog. `permission_required` includes `missing_permissions` for that surface's
startup requirements. A policy restriction takes precedence over missing grants.
Present review for the exact instance, then refresh the authoritative catalog
before opening a fresh surface. Do not request every plugin permission, treat
unknown read failures as permission requests, or replay business operations.

Build/package checks, install eligibility, preview admission and business
verification are distinct evidence. Report only checks actually performed.
Exercise first use with no grants, refusal, explicit authorization, configured
operation, installation consent, opening the installed instance, revocation and
reopen through the actual host boundary. Deterministic
providers can verify integration; they do not establish real-model quality.

The host may expose `Host.InspectPluginCapabilities` through trusted author tools.
It is read-only, returns current facts and never invokes capability adapters or
grants permissions. Its generated declaration examples describe the contract;
authors choose the methods needed by their application.
