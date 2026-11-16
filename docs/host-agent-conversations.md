# Scoped Agent conversations

`pkg/agentconversation` publishes the `agent.conversation` capability and
`@floegence/redevplugin-ui/agent-conversation` provides the generated client and
framework-neutral author API. The host supplies the Agent engine, canonical
history, scoped business metadata and official view. ReDevPlugin supplies the
existing permission, confirmation, execution, stream and sandbox boundaries.
This capability does not depend on a particular model provider or Agent engine.

## Plugin author API

Declare the exact published contract pin and its methods in the plugin manifest,
then use the existing `PluginBridgeClient`:

```ts
import { createAgentClient, defineAgentProfile } from "@floegence/redevplugin-ui/agent-conversation";

const agents = createAgentClient(bridge, { capabilityBinding: "agent" });
const agent = await agents.bindAgent({
  objectKey: selectedObject.id,
  profile: defineAgentProfile({
    id: "assistant",
    instructions: "Help the user operate the selected object.",
    methods: ["document.read", "document.apply"],
  }),
});
const conversation = await agent.conversations.open({ key: "main" });
const view = await agent.mount(container, conversation);
// Later: view.dispose() detaches presentation without stopping accepted work.
```

Custom UI uses `conversation.send({ requestId, text })` and
`conversation.observe({ after, signal })`. Keep the request ID until its receipt
is resolved. An uncertain response must be queried with `receipt(requestId)`;
neither the SDK nor the host may invent a replacement request and replay work.
Profiles request methods, skills, host tools and MCP connection slots. They do
not grant any resources. Method schemas come from the installed manifest.
Context methods must be read-only. Inline skill content is untrusted plugin
instruction, never a replacement for host policy. Connection configuration is
handled by the trusted host and returns references/status, never credentials.
`mcp_components` may declare Streamable HTTP connections or host-executed stdio
services with arguments and credential references. The host validates transport
shape, resolves secrets through its vault and requires explicit user admission
before starting a service. This does not introduce a native plugin backend,
install hook or alternative runtime. MCP tools, resources and prompts use the
host's existing connection manager and retain that component's lifecycle.

## Host ownership contract

The host binds each `object_key` and profile to the verified installation, user
and environment. Every returned binding and conversation ID is rechecked against
that owner on every request. Supplied IDs are references, never authority.
Opening a conversation is idempotent and does not launch a model turn. Binding
and conversation revisions use compare-and-set for updates/deletion. Conflicts
and unknown outcomes remain explicit; the SDK does not silently retry writes.
Rebinding an unchanged profile restores the binding; changing it requires
`expected_revision` and must not preserve grants for newly requested resources.

The host uses its existing canonical conversation engine. Plugin conversations,
forks, children, attachments, events and derived indexes must remain scoped to
their business binding. Ordinary chat lists, searches, direct reads and live
feeds cannot expose them. Deleting a binding uses the engine's formal lifecycle;
the host retains recoverable deletion intent before removing its metadata.
Uninstall, disable, upgrade, authorization changes and reconnect must revalidate
the actual plugin instance and current grants. A detached view is not a request
to cancel a turn. Background execution needs an explicit background grant.

`observe` emits public semantic events. `cursor` is an opaque host cursor;
`reset` asks the client to load a fresh snapshot when retention has expired.
Details must exclude credentials, unrelated conversations and private model
reasoning. Subscription cancellation only stops observation.

## Official views and complete host clients

Register `capability.Registration.View` with an immutable `NewViewBundle`.
`view.json` follows `spec/plugin/capability-view.schema.json`. The module exports
`mount({ container, bridge, input, signal })` and returns `{ dispose() }`.
The SDK mounts it in a ShadowRoot with the declared styles. Hosts must route
portals, focus handling and theme context into that root. Loading a view does
not execute a model or confer any method permission.

The platform serves only declared exact-pinned capabilities inside an admitted
plugin origin. Resources use the existing Web asset session and revocation
boundary. No management cookie, alternate gateway, remote module URL or relaxed
CSP is introduced. View bytes contain no user data or credentials.

`bind` negotiates `client_protocol` for the host's complete official UI.
`client.read`, `client.write`, `client.execute` and `client.delete` carry that
versioned protocol's operation name and JSON payload. The host maintains one
closed operation catalog with input/output schemas and an exact effect for each
operation. Unknown protocols, operations, mismatched effects and references
outside the binding are rejected before dispatch. These are not HTTP proxies,
arbitrary internal method dispatch or access to user-global settings. The
official view and the host's ordinary UI consume the same canonical operations.
`client.observe` observes only that binding's live projection. The outer stream
does not become another transcript or execution owner.

Authorization-sensitive operations are separate: `approve` and `configure`
require the platform's trusted, single-use confirmation bound to every request
field. The host confirmation handler displays the authoritative pending request
or configuration panel. A plugin-provided boolean or a generic `client.execute`
operation must never approve an action, grant tools, expose a credential or
change account settings. Configuration cancellation preserves the original
selection and draft. Hosts must publish and test their complete view feature
matrix; empty stubs do not constitute support.

Configuration may identify a conversation within the same binding and include
a host-protocol JSON proposal. This lets an embedded view open the exact model,
permission or computer-control editor without losing its draft. The proposal
is untrusted initial form data, not a grant or approved configuration. Both
optional fields participate in the confirmation hash; the host revalidates the
conversation's ownership and presents the actual choices before committing.

## Calling back into native plugin methods

A trusted capability adapter retains the exact platform-issued
`capability.ExecutionBinding` and calls `Host.InvokeCapabilityMethod` with the
current authenticated session and a selected native method. The adapter must
enforce its profile's method selection. `DescribeCapabilityMethods` resolves
that selection to copied native method schemas from the exact installed
manifest without granting execution. The platform checks the original
binding's expiry and revisions, current session/permissions/local policy,
request/response schemas, exact live surface channel, destination target,
confirmation and normal execution leases. Only worker and surface routes are
allowed; capability recursion and lifecycle-only methods are rejected. Mutating
callbacks require an execute source invocation and a writable session.

`PrepareCapabilityMethodConfirmation` prepares the existing native method
confirmation. Hosts show it in trusted UI and retain the same request, plan,
target and revision evidence for execution. They do not synthesize browser
gateway tokens or auto-approve the method because an Agent requested it. Worker
methods use their published runtime; surface methods require their exact live
receiver and never substitute another window after closure. Dispatched effects
with an uncertain result retain the existing `mutation.OutcomeUnknown` contract.
