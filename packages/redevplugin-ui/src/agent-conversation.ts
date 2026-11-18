import { AgentConversationClient, isAgentConversationBusinessError, type AgentConversationBindRequest, type AgentConversationBindResponse, type AgentConversationOpenResponse, type AgentConversationObserveEvent } from "./agent-conversation.gen.js";
import { mountCapabilityView, type CapabilityView } from "./capability-view.js";
import type { PluginBridgeClient, PluginBridgeRequestOptions } from "./plugin.js";
import { PluginBridgeError } from "./errors.js";

export * from "./agent-conversation.gen.js";
export type AgentProfile = AgentConversationBindRequest["profile"];
export function isConversationClosed(error: unknown): boolean {
  return error instanceof ConversationClosedError || isAgentConversationBusinessError(error) && error.details.business_error_code === "CONVERSATION_CLOSED";
}
class ConversationClosedError extends Error {
  constructor() { super("Conversation has ended"); this.name = "ConversationClosedError"; }
}
export type AgentConfigurationInput = { area: "models" | "tools" | "skills" | "mcp" | "permissions" | "computer"; slot?: string; conversation?: AgentConversation; proposal?: unknown };

/** Defines behavior and requested resources. This is never an authority grant. */
export function defineAgentProfile(profile: AgentProfile): AgentProfile {
  return structuredClone(profile);
}

export interface AgentClientOptions {
  /** The capability binding declared by this plugin's manifest. */
  capabilityBinding: string;
}

export function createAgentClient(bridge: PluginBridgeClient, options: AgentClientOptions) {
  const client = new AgentConversationClient(bridge);
  return Object.freeze({
    async openAgent(roleID: string, requestOptions?: PluginBridgeRequestOptions): Promise<BoundAgent> {
      const binding = await client.openRole({ role_id: roleID }, requestOptions);
      return new BoundAgent(bridge, client, options.capabilityBinding, binding);
    },
    async bindAgent(input: { objectKey: string; profile: AgentProfile; expectedRevision?: number }, requestOptions?: PluginBridgeRequestOptions): Promise<BoundAgent> {
      const binding = await client.bind({ object_key: input.objectKey, profile: input.profile, ...(input.expectedRevision === undefined ? {} : { expected_revision: input.expectedRevision }) }, requestOptions);
      return new BoundAgent(bridge, client, options.capabilityBinding, binding);
    },
  });
}

export class BoundAgent {
  readonly #bridge: PluginBridgeClient;
  readonly #client: AgentConversationClient;
  readonly #capabilityBinding: string;
  #binding: AgentConversationBindResponse;

  constructor(bridge: PluginBridgeClient, client: AgentConversationClient, capabilityBinding: string, binding: AgentConversationBindResponse) {
    this.#bridge = bridge;
    this.#client = client;
    this.#capabilityBinding = capabilityBinding;
    this.#binding = structuredClone(binding);
  }

  get binding(): Readonly<AgentConversationBindResponse> { return structuredClone(this.#binding); }

  readonly temporary = Object.freeze({
    reply: async (input: { text: string; history?: readonly { user: string; assistant: string }[] }, options?: PluginBridgeRequestOptions): Promise<{ text: string }> => {
      const result = await this.#client.clientExecute({ binding_id: this.#binding.binding_id, protocol: this.#binding.client_protocol, operation: "temporary.reply", input_json: JSON.stringify(input) }, options);
      const reply: unknown = JSON.parse(result.output_json);
      if (!reply || typeof reply !== "object" || !("text" in reply) || typeof reply.text !== "string") throw new TypeError("Invalid temporary reply");
      return { text: reply.text };
    },
  });

  readonly conversations = Object.freeze({
    open: async (input: { key: string; title?: string; lifetime?: "persistent" | "temporary" }, options?: PluginBridgeRequestOptions): Promise<AgentConversation> => {
      const snapshot = await this.#client.open({ binding_id: this.#binding.binding_id, ...input }, options);
      if (input.lifetime === "temporary" && snapshot.lifetime !== "temporary") throw new TypeError("Host did not open a temporary conversation");
      return new AgentConversation(this, this.#client, snapshot);
    },
    get: async (id: string, options?: PluginBridgeRequestOptions): Promise<AgentConversation> => {
      const snapshot = await this.#client.get({ binding_id: this.#binding.binding_id, conversation_id: id }, options);
      return new AgentConversation(this, this.#client, snapshot);
    },
    list: async (input: { cursor?: string; archived?: boolean } = {}, options?: PluginBridgeRequestOptions) => {
      const page = await this.#client.list({ binding_id: this.#binding.binding_id, ...input }, options);
      return { conversations: page.conversations.map(snapshot => new AgentConversation(this, this.#client, snapshot)), nextCursor: page.next_cursor };
    },
  });

  async reviewConfiguration(input: AgentConfigurationInput, options?: PluginBridgeRequestOptions): Promise<"saved" | "cancelled"> {
    try { await this.configure(input, options); return "saved"; }
    catch (error) {
      if (error instanceof PluginBridgeError && error.errorCode === "PLUGIN_CONFIRMATION_REJECTED" &&
          typeof error.details === "object" && error.details !== null && "review" in error.details && error.details.review === "dismissed") return "cancelled";
      throw error;
    }
  }

  async configure(input: AgentConfigurationInput, options?: PluginBridgeRequestOptions): Promise<void> {
    if (input.conversation?.closed) throw new ConversationClosedError();
    if (input.conversation && input.conversation.agent !== this) throw new Error("Conversation belongs to another Agent binding");
    const proposal = input.proposal === undefined ? undefined : JSON.stringify(input.proposal);
    if (input.proposal !== undefined && proposal === undefined) throw new TypeError("Configuration proposal must be JSON");
    const result = await this.#client.configure({ binding_id: this.#binding.binding_id, area: input.area, slot: input.slot ?? "", ...(input.conversation ? { conversation_id: input.conversation.id } : {}), ...(proposal === undefined ? {} : { proposal_json: proposal }) }, options);
    this.#binding = { ...this.#binding, ...result };
  }

  async updateContext(context: unknown, options?: PluginBridgeRequestOptions): Promise<void> {
    const encoded = JSON.stringify(context);
    if (encoded === undefined) throw new TypeError("Agent context must be JSON");
    const result = await this.#client.context({ binding_id: this.#binding.binding_id, revision: this.#binding.revision, context_json: encoded }, options);
    this.#binding = { ...this.#binding, revision: result.revision };
  }

  async delete(options?: PluginBridgeRequestOptions): Promise<void> {
    await this.#client.dispose({ binding_id: this.#binding.binding_id, revision: this.#binding.revision }, options);
  }

  /** Mounts the official host view; disposing the result only detaches UI. */
  mount(container: HTMLElement, conversation: AgentConversation, options: { appearance?: "embedded" | "page"; history?: boolean; signal?: AbortSignal } = {}): Promise<CapabilityView> {
    if (conversation.closed) throw new ConversationClosedError();
    if (conversation.agent !== this) throw new Error("Conversation belongs to another Agent binding");
    return mountCapabilityView(container, {
      bindingID: this.#capabilityBinding,
      bridge: this.#bridge,
      signal: options.signal,
      input: { binding_id: this.#binding.binding_id, conversation_id: conversation.id, ...(conversation.snapshot.lifetime === "temporary" ? { lifetime: "temporary" } : {}), protocol: this.#binding.client_protocol, preset: "official", appearance: options.appearance ?? "embedded", history: options.history ?? true },
    });
  }
}

export class AgentConversation {
  readonly agent: BoundAgent;
  readonly #client: AgentConversationClient;
  #snapshot: AgentConversationOpenResponse;
  readonly #end = new AbortController();
  #closing?: Promise<void>;

  constructor(agent: BoundAgent, client: AgentConversationClient, snapshot: AgentConversationOpenResponse) {
    this.agent = agent;
    this.#client = client;
    this.#snapshot = structuredClone(snapshot);
  }

  get id(): string { return this.#snapshot.conversation_id; }
  get snapshot(): Readonly<AgentConversationOpenResponse> { return structuredClone(this.#snapshot); }
  get closed(): boolean { return this.#end.signal.aborted; }
  #scope() {
    if (this.closed) throw new ConversationClosedError();
    return { binding_id: this.agent.binding.binding_id, conversation_id: this.id };
  }

  /** Release this handle. A temporary conversation also ends for every holder. */
  async close(options?: PluginBridgeRequestOptions): Promise<void> {
    if (this.closed) return;
    if (!this.#closing) this.#closing = (async () => {
      if (this.#snapshot.lifetime === "temporary") {
        try { await this.#client.close(this.#scope(), options); }
        catch (error) { if (!isConversationClosed(error)) throw error; }
      }
      this.#end.abort(new ConversationClosedError());
    })().finally(() => { this.#closing = undefined; });
    await this.#closing;
  }

  async refresh(options?: PluginBridgeRequestOptions): Promise<void> {
    this.#snapshot = await this.#client.get(this.#scope(), options);
  }

  async send(input: { requestId: string; text: string; modelID?: string }, options?: PluginBridgeRequestOptions) {
    return this.#client.send({ ...this.#scope(), request_id: input.requestId, text: input.text, ...(input.modelID ? { model_id: input.modelID } : {}) }, options);
  }

  receipt(requestId: string, options?: PluginBridgeRequestOptions) {
    return this.#client.receipt({ ...this.#scope(), request_id: requestId }, options);
  }

  async stop(requestId: string, options?: PluginBridgeRequestOptions): Promise<void> {
    await this.#client.stop({ ...this.#scope(), request_id: requestId }, options);
  }

  async update(patch: { title?: string; archived?: boolean }, options?: PluginBridgeRequestOptions): Promise<void> {
    this.#snapshot = await this.#client.update({ ...this.#scope(), revision: this.#snapshot.revision, ...patch }, options);
  }

  async fork(input: { key: string; requestId: string; sourceItemID?: string }, options?: PluginBridgeRequestOptions): Promise<AgentConversation> {
    const snapshot = await this.#client.fork({ ...this.#scope(), key: input.key, request_id: input.requestId, ...(input.sourceItemID ? { source_item_id: input.sourceItemID } : {}) }, options);
    return new AgentConversation(this.agent, this.#client, snapshot);
  }

  async delete(options?: PluginBridgeRequestOptions): Promise<void> {
    await this.#client.delete({ ...this.#scope(), revision: this.#snapshot.revision }, options);
  }

  async *observe(input: { after?: string; signal?: AbortSignal } = {}): AsyncIterableIterator<AgentConversationObserveEvent> {
    const scope = this.#scope();
    const signal = input.signal ? AbortSignal.any([input.signal, this.#end.signal]) : this.#end.signal;
    if (this.#snapshot.lifetime === "temporary") {
      let after = input.after;
      while (!this.closed) {
        let page;
        try { page = await this.#client.readEvents({ ...scope, ...(after ? { after } : {}) }, { signal }); }
        catch (error) {
          if (this.closed) return;
          if (!isConversationClosed(error)) throw error;
          this.#end.abort(error);
          yield { kind: "closed", cursor: after ?? "closed", conversation_id: this.id };
          return;
        }
        for (const event of page.events) {
          if (this.closed) return;
          if (event.kind === "closed") this.#end.abort(new ConversationClosedError());
          after = event.cursor;
          yield event;
        }
        if (!page.events.length) await observationPause(signal);
      }
      return;
    }
    input = { ...input, signal };
    const stream = await this.#client.observe({ ...this.#scope(), ...(input.after ? { after: input.after } : {}) }, { signal: input.signal });
    try {
      while (true) {
        input.signal?.throwIfAborted();
        const batch = await stream.read({ signal: input.signal });
        for (const event of batch.events) yield event.data;
        if (batch.done) return;
        if (batch.events.length === 0) await observationPause(input.signal);
      }
    } finally {
      await stream.cancel("conversation_observer_detached");
    }
  }
}

function observationPause(signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const cancel = () => { clearTimeout(timer); reject(signal?.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", cancel); resolve(); }, 250);
    signal?.addEventListener("abort", cancel, { once: true });
  });
}
