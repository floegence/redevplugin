# Scoped Agent conversations

Use the SDK version reported with this guide. Copy `binding` into manifest
`capability_bindings`, and only the needed `methods[].declaration` entries into
`methods`. When renaming `binding_id`, update the routes and `capabilityBinding`.

For a role shipped by the plugin, declare `agent.conversation.role.open` and include
`agents.json` at the root of the built package (current templates copy `ui/agents.json` there).
It is an array of ordinary profiles, e.g. `[{"id":"assistant","instructions":"Help with this object.","methods":[]}]`.
Keep the ID stable. When adopting an existing dynamic binding use its original profile ID
and add its exact `object_key` to this declaration. Never infer or replace a user's binding.

```ts
import { createAgentClient } from
  "@floegence/redevplugin-ui/agent-conversation";

const client = createAgentClient(bridge, { capabilityBinding: "agent" });
const agent = await client.openAgent("assistant");
// For a single ephemeral text exchange, declare client.execute and use
// agent.temporary.reply({ text }, { signal }). For a saved conversation:
const conversation = await agent.conversations.open({ key: "main" });
// From a user settings action, using the trusted host configuration panel:
const outcome = await agent.reviewConfiguration({ area: "models", conversation });
// "cancelled" is a normal return to the plugin. Only "saved" confirms completion.
```

Use `bindAgent` for runtime-edited profiles. Editing one requires its known revision.
Never guess the revision, create another key on conflict, or match English exception text.

The example needs manifest routes for `agent.conversation.role.open`, `.open` and
`.configure`. Profile `methods` has a different meaning: it selects native plugin
methods the Agent may call back into. It may be empty for a text-only Agent;
manifest capability routes still must be declared.

For a custom UI or a headless Agent, declare `.send`, `.result` and the
observation method for the selected lifetime. Declare `.cancel_send` only if
the user should be able to cancel submitted work. For example:

```ts
const sent = await conversation.send(text, { requestId, model, effort });
const answer = await sent.result({ signal });
if (answer.status === "completed") renderAnswer(answer.text);
```

`model` and `effort` are optional. `agent.models.list()` (declare `.models`)
returns the selectable models and their supported reasoning levels. Keep
provider credentials in the host. Save a stable `requestId` before a send if
the user must resume after reconnect. To recover, call
`conversation.findSend(requestId).result()` on the same conversation. Completed
results may have empty text. Failed results may include a stable `failureCode`
for display or diagnosis; they never contain a raw provider error. Aborting the wait only detaches this reader;
`sent.cancel()` explicitly targets the original pending input or execution.
Choose the lifetime by how long the user needs the history. For multi-turn
context limited to this window, use `agent.conversations.open({ key, lifetime: "temporary" })`.
Omit `lifetime` for history that must survive reopening. Use `temporary.reply` for one exchange.
Declare `.events.read` for `observe()` on temporary handles and `.close` for
`await conversation.close()`. Keep the same handle across turns and panel changes.
Reopen the same key inside the same live window to reconnect. A closed window or
an explicit close ends its conversation; a new open cannot reuse the old ID.
Handle `isConversationClosed(error)` or the `closed` observation by releasing the
stale handle. A transport error alone does not mean the session ended. Never replay
an uncertain send or substitute a saved chat. Closing a saved handle releases
only the local handle; deleting history is a separate action.
Use public observations to render changes. The SDK uses an initial snapshot
and subsequent changes to wake result readers. It reads complete final text
from the original request, never from event fragments or timers.

For a custom conversation interface, open a packaged role with the public SDK.
Declare `.threads`, `.locate`, and the data routes you actually display. For
private and picked conversations these are `.get`, `.history`, `.body`, and
`.window`. For the host library declare `.library.list`, `.library.messages`,
`.library.body`, and `.library.window`. A broad library grant includes future
ordinary conversations in the authorized environment. Prefer `.pick` when the
user only needs to share one conversation. An identifier never grants access.

```ts
import { createFlowerClient } from "@floegence/redevplugin-ui/agent-conversation";
const flower = await createFlowerClient(bridge, { capabilityBinding: "agent", role: "assistant" });
const page = await flower.threads.list({ limit: 30 });
const selected = await flower.threads.pick({ access: "read" });
if (selected) {
  for await (const view of selected.watch({ signal })) render(view.items);
}
```

Open a listed ID using `flower.threads.open(id)`. `history` returns ordered
messages and `nextCursor`; `body(item.id, { cursor })` reads complete text in
pages. `attachment(item.id, index, { cursor })` additionally requires the
separate original-file grant; names, media types and sizes alone do not grant
file access. Restart `watch` with the same handle after reconnect. A revoked
resource requires fresh permission. Cancelling a picker returns `null`.

`flower.threads.create({ key, lifetime: "temporary" })` uses the bound role.
Add `agent: "host"` to use the host persona in the same window without reading or creating saved history. Both temporary roles use `.open` and the same thread handle.
`flower.threads.create({ agent: "host", key })` creates a saved ordinary
conversation with `.library.create`. The library's `.library.send`, `.library.result`
and `.library.cancel_send` routes work with the same `send` and `findSend`
handles. Reading the library does not authorize sending or management. A
selected `continue` grant additionally needs the ordinary `.send` route and
execution permission. Inspect exact routes and grants with the author tools.

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
Use scoped surface startup requirements as described in `capabilities`; keep
Agent actions in an explicit setup state until the host's permission review is
complete. Do not make a top-level rejected `bindAgent` promise erase the whole
interface or remove the requested model-configuration control.

`agent.binding.available` reports binding availability, not universal model
readiness or proof of a successful response. Model selection and credentials
belong to the host; never place credentials in plugin code or persistent context.
The author's own chat model and permission mode are not plugin authorization.

Check declarations and authorization separately, then exercise the requested
flow. Keep configuration available when setup fails and report the structured blocker.
