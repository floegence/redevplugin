# Scoped Agent conversations

Use `@floegence/redevplugin-ui/agent-conversation` from the platform version
reported with this document. The returned `binding` is an exact manifest
`capability_bindings` entry. The returned `methods` are generated from that same
published contract: copy the needed `declaration` entries into manifest `methods`.
If changing `binding_id`, change both the method routes and `capabilityBinding`.
Do not add every method or grant every permission without considering usage.

```ts
import { createAgentClient, defineAgentProfile } from
  "@floegence/redevplugin-ui/agent-conversation";

const client = createAgentClient(bridge, { capabilityBinding: "agent" });
const agent = await client.bindAgent({
  objectKey: "stable-business-object",
  profile: defineAgentProfile({
    id: "assistant",
    instructions: "Help with this business object.",
    methods: [],
  }),
});
const conversation = await agent.conversations.open({ key: "main" });
// From a user settings action, using the trusted host configuration panel:
await agent.configure({ area: "models", conversation });
```

The example needs manifest routes for `agent.conversation.bind`, `.open` and
`.configure`. Profile `methods` has a different meaning: it selects native plugin
methods the Agent may call back into. It may be empty for a text-only Agent;
manifest capability routes still must be declared.

For a custom UI, declare `.send`, `.observe`, `.receipt` and `.stop` as used.
Start observation before sending. Retain each request ID and query its receipt
when the send outcome is unknown; do not generate a replacement ID and replay.
Observe only public semantic events. A completed stream must not be inferred
from an arbitrary text fragment or a timer.

For the official view, use `agent.mount(container, conversation)`. Declare the
methods needed by its enabled controls, including `client.read`, `client.write`,
`client.execute`, `client.delete`, `client.observe`, `configure` and `approve`.
The host provides the official feature matrix. Mounting the view grants nothing.
Disposing the view detaches presentation and does not cancel accepted work.

`agent.configure` requests trusted host configuration. The platform requires a
single-use confirmation bound to the exact request; the host opens its settings
panel and commits the reviewed values before returning the resulting status.
The capability response returning availability does not mean the setting is a
no-op. Cancellation leaves the previous settings intact. Configuration cannot
bootstrap missing plugin grants: binding and configuration themselves require
their declared routes and current permissions. Use the host's instance permission
review first when those permissions are missing.

Render independent local content before binding or opening a conversation.
For example, a local game board can remain usable before the Agent is available.
Use scoped surface startup requirements as described in `capabilities`; keep
Agent actions in an explicit setup state until the host's permission review is
complete. Do not make a top-level rejected `bindAgent` promise erase the whole
interface or remove the requested model-configuration control.

`agent.binding.available` reports binding availability, not universal model
readiness or proof of a successful response. Model selection and credentials
belong to the host; never place credentials in plugin code or persistent context.
The author's own chat model and permission mode are not plugin authorization.

Validate declaration and authorization separately before testing the actual
business flow. Preserve a usable configuration action when setup fails and
report the structured blocker. Do not remove requested behavior based only on
one backend branch or a generic permission-denied message.
