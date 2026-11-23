import { AgentConversationClient, isAgentConversationBusinessError, type AgentConversationBindRequest, type AgentConversationBindResponse, type AgentConversationOpenResponse, type AgentConversationObserveEvent } from "./agent-conversation.gen.js";
import { mountCapabilityView, type CapabilityView } from "./capability-view.js";
import type { PluginBridgeClient, PluginBridgeRequestOptions } from "./plugin.js";
import { PluginBridgeError } from "./errors.js";
import type { AgentConversationWindowResponse, AgentConversationHistoryResponse, AgentConversationResultResponse } from "./agent-conversation.gen.js";

export * from "./agent-conversation.gen.js";
export type AgentProfile = AgentConversationBindRequest["profile"];
export type SendResult = { status: "completed"; text: string } | { status: "failed"; failureCode?: string } | { status: "cancelled" | "interrupted" | "unknown" };
export interface ConversationSend {
  readonly requestId: string;
  result(options?: PluginBridgeRequestOptions): Promise<SendResult>;
  cancel(options?: PluginBridgeRequestOptions): Promise<void>;
}
type HistoryOptions = { cursor?: string; limit?: number; signal?: AbortSignal };
type WindowOptions = { limit?: number; signal?: AbortSignal };
type ReaderScope = { binding_id: string; conversation_id: string } | { binding_id: string; thread_id: string };
type SendOptions = PluginBridgeRequestOptions & { requestId?: string; model?: string; effort?: string };
function optional<T extends object>(fields:T):Partial<T> {return Object.fromEntries(Object.entries(fields).filter(([,value])=>value!==undefined)) as Partial<T>;}
export type ConversationWindow = NonNullable<AgentConversationWindowResponse["view"]>;
export type ConversationMessage = AgentConversationHistoryResponse["items"][number];

// Both origins use the same reader. Transport scopes and bridge field names
// stay inside the SDK; a resource selector is never an authorization grant.
export class ConversationReader {
  readonly #client: AgentConversationClient;
  readonly #scope: () => ReaderScope;
  readonly #end: AbortSignal;
  constructor(client: AgentConversationClient, scope: () => ReaderScope, end: AbortSignal) {
    this.#client = client; this.#scope = scope; this.#end = end;
  }
  #signal(signal?: AbortSignal) { return signal ? AbortSignal.any([signal, this.#end]) : this.#end; }
  async history({ cursor, limit, signal }: HistoryOptions = {}) {
    const scope = this.#scope(), transport = { signal: this.#signal(signal) };
    const page = "thread_id" in scope ? await this.#client.libraryMessages({ ...scope, ...optional({cursor, limit}) }, transport) : await this.#client.history({ ...scope, ...optional({cursor, limit}) }, transport);
    return { items: page.items, nextCursor: page.next_cursor };
  }
  async body(itemId: string, { cursor, signal }: Omit<HistoryOptions,"limit"> = {}) {
    const scope = this.#scope(), transport = { signal: this.#signal(signal) };
    const page = "thread_id" in scope ? await this.#client.libraryBody({ ...scope, ref:itemId, ...optional({cursor}) }, transport) : await this.#client.body({ ...scope, ref:itemId, ...optional({cursor}) }, transport);
    return { text: page.text, nextCursor:page.next_cursor };
  }
  async attachment(itemId:string,index:number,{cursor,signal}:Omit<HistoryOptions,"limit">={}) {
    const scope=this.#scope(),fields={ref:itemId,index,...optional({cursor})},options={signal:this.#signal(signal)};
    const page="thread_id" in scope ? await this.#client.libraryAttachment({...scope,...fields},options) : await this.#client.attachment({...scope,...fields},options);
    return {bytes:Uint8Array.from(atob(page.data),c=>c.charCodeAt(0)),nextCursor:page.next_cursor};
  }
  async *watch(options: WindowOptions = {}): AsyncIterableIterator<ConversationWindow> {
    for await (const page of this.windows(options)) if (page.view) yield page.view;
  }
  protected async *windows({ limit, signal }: WindowOptions = {}) {
    const transport = { signal:this.#signal(signal) };
    let after: string | undefined;
    while (!transport.signal.aborted) {
      const scope = this.#scope();
      const next: AgentConversationWindowResponse = "thread_id" in scope ? await this.#client.libraryWindow({ ...scope, ...optional({limit, after}) }, transport) : await this.#client.window({ ...scope, ...optional({limit, after}) }, transport);
      if (!next.cursor || (!next.view && next.cursor !== after)) throw new TypeError("Invalid conversation window");
      after = next.cursor;
      yield next;
    }
  }
}

function originalSend(requestId: string, end: AbortSignal,
  page: (cursor: string | undefined, signal: AbortSignal) => Promise<AgentConversationResultResponse>,
  updates: (signal: AbortSignal) => AsyncIterable<unknown>, cancel: (options?: PluginBridgeRequestOptions) => Promise<unknown>): ConversationSend {
  return Object.freeze({ requestId, cancel: async (options?: PluginBridgeRequestOptions) => { await cancel(options); },
    async result(options?: PluginBridgeRequestOptions): Promise<SendResult> {
      const signal=options?.signal ? AbortSignal.any([options.signal,end]) : end;
      const read = async ():Promise<SendResult | undefined> => {
        const chunks:string[]=[],seen=new Set<string>();let cursor:string|undefined;
        for (;;) {
          signal.throwIfAborted();const next=await page(cursor,signal);
          if (next.state!=="completed") {
            if(cursor)throw new TypeError("Invalid send result page");
            switch(next.state){
              case "accepted":case "waiting":case "running":return undefined;
              case "failed":return {status:"failed",...optional({failureCode:next.failure_code})};
              default:return {status:next.state};
            }
          }
          if(typeof next.text!=="string")throw new TypeError("Missing final assistant text");chunks.push(next.text);
          if(next.next_cursor===undefined)return {status:"completed",text:chunks.join("")};
          if(!next.next_cursor || seen.has(next.next_cursor))throw new TypeError("Invalid send result cursor");
          seen.add(next.next_cursor);cursor=next.next_cursor;
        }
      };
      const immediate=await read();if(immediate)return immediate;
      for await (const update of updates(signal)) {if (update === undefined) continue; const settled=await read();if(settled)return settled;}
      signal.throwIfAborted();throw new Error("Conversation observation ended before the send settled");
    },
  });
}

class SharedConversation extends ConversationReader {
  readonly #end: AbortController;
  readonly #client: AgentConversationClient;
  readonly #target: {binding_id:string;thread_id:string};
  constructor(client:AgentConversationClient, target:{binding_id:string;thread_id:string}, readonly title:string) {
    const end=new AbortController();super(client,()=>{end.signal.throwIfAborted();return target;},end.signal);
    this.#end=end;this.#client=client;this.#target=target;
  }
  get id(){return this.#target.thread_id;}
  close(){this.#end.abort(new ConversationClosedError());}
  async rename(title:string,options?:PluginBridgeRequestOptions){this.#end.signal.throwIfAborted();await this.#client.renameLibraryThread({...this.#target,title},options);}
  async delete(options?:PluginBridgeRequestOptions){this.#end.signal.throwIfAborted();await this.#client.deleteLibraryThread(this.#target,options);this.close();}
  async send(text:string,{requestId=crypto.randomUUID(),model,effort,signal}:SendOptions={}) {
    this.#end.signal.throwIfAborted(); await this.#client.librarySend({...this.#target,text,request_id:requestId,...optional({model_id:model,effort})},{signal});return this.findSend(requestId);
  }
  findSend(requestId:string):ConversationSend {
    const target={...this.#target,request_id:requestId};
    return originalSend(requestId,this.#end.signal,(cursor,signal)=>this.#client.libraryResult({...target,...optional({cursor})},{signal}),signal=>this.windows({signal}),options=>{this.#end.signal.throwIfAborted();return this.#client.libraryCancelSend(target,options);});
  }
}
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

/** Open a packaged role with openAgent, or bind a runtime-edited profile with bindAgent. */
export function createAgentClient(bridge: PluginBridgeClient, options: AgentClientOptions) {
  const client = new AgentConversationClient(bridge);
  const openAgent=async(roleID:string,requestOptions?:PluginBridgeRequestOptions)=>{const binding=await client.openRole({role_id:roleID},requestOptions);return new BoundAgent(bridge,client,options.capabilityBinding,binding);};
  return Object.freeze({
    openAgent,
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

  readonly threads = Object.freeze({
    create: async (input: {agent?:"host"|"binding";key?:string; title?:string; lifetime?:"persistent"|"temporary"} = {}, options?:PluginBridgeRequestOptions) => {
      const {agent,key=crypto.randomUUID(),title,lifetime}=input;
      if(agent!=="host")return this.conversations.open({key,...optional({title,lifetime})},options);
      if(lifetime==="temporary") {
        const snapshot=await this.#client.open({binding_id:this.#binding.binding_id,agent,key,lifetime,...optional({title})},options);
        if(snapshot.lifetime!=="temporary")throw new TypeError("Host did not open a temporary conversation");
        return new AgentConversation(this,this.#client,snapshot);
      }
      const item=await this.#client.createLibraryThread({binding_id:this.#binding.binding_id,request_id:key,...optional({title})},options);
      return new SharedConversation(this.#client,{binding_id:this.#binding.binding_id,thread_id:item.id},item.title);
    },
    open: async (id:string, options?:PluginBridgeRequestOptions) => {
      const item=await this.#client.locate({binding_id:this.#binding.binding_id,id},options);
      if(item.origin==="host")return new SharedConversation(this.#client,{binding_id:this.#binding.binding_id,thread_id:id},item.title);
      const snapshot=await this.#client.get({binding_id:this.#binding.binding_id,conversation_id:id},options);
      return new AgentConversation(this,this.#client,snapshot,item.origin==="selected");
    },
    pick: async ({access="read",signal}:{access?:"read"|"continue";signal?:AbortSignal}={}) => {
      try {const snapshot=await this.#client.pick({binding_id:this.#binding.binding_id,request_id:crypto.randomUUID(),access},{signal});return new AgentConversation(this,this.#client,snapshot,true);}
      catch(error){if(dismissedReview(error))return null;throw error;}
    },
    list: async (input:{cursor?:string;query?:string;limit?:number;agent?:"host"|"binding"}={}, options?:PluginBridgeRequestOptions) => {
      const page=await this.#client.threads({...optional(input),binding_id:this.#binding.binding_id},options);
      return { items:page.items, nextCursor:page.next_cursor };
    },
  });

  readonly models = Object.freeze({
    list: (options?: PluginBridgeRequestOptions) => this.#client.listModels({ binding_id: this.#binding.binding_id }, options),
  });

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
      if (dismissedReview(error)) return "cancelled";
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

export class AgentConversation extends ConversationReader {
  readonly agent: BoundAgent;
  readonly #client: AgentConversationClient;
  #snapshot: AgentConversationOpenResponse;
  readonly #end: AbortController;
  #closing?: Promise<void>;
  readonly #selected:boolean;

  constructor(agent: BoundAgent, client: AgentConversationClient, snapshot: AgentConversationOpenResponse, selected=false) {
    const end = new AbortController();
    super(client, () => this.#scope(), end.signal); this.#end=end;
    this.agent = agent;
    this.#client = client;
    this.#snapshot = structuredClone(snapshot);
    this.#selected=selected;
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

  async send(input: { requestId: string; text: string; modelID?: string }, options?: PluginBridgeRequestOptions): ReturnType<AgentConversationClient["send"]>;
  async send(input: string, options?: PluginBridgeRequestOptions & { requestId?: string; model?: string; effort?: string }): Promise<ConversationSend>;
  async send(input: { requestId: string; text: string; modelID?: string } | string, options?: PluginBridgeRequestOptions & { requestId?: string; model?: string; effort?: string }) {
    if (typeof input !== "string") return this.#client.send({ ...this.#scope(), request_id: input.requestId, text: input.text, ...(input.modelID ? { model_id: input.modelID } : {}) }, options);
    const { requestId = crypto.randomUUID(), model, effort, ...transport } = options ?? {};
    await this.#client.send({ ...this.#scope(), request_id: requestId, text: input, ...(model === undefined ? {} : { model_id: model }), ...(effort === undefined ? {} : { effort }) }, transport);
    return this.findSend(requestId);
  }

  /** Address one original send, including after reconnect. No message is submitted. */
  findSend(requestId: string): ConversationSend {
    const target = () => ({ ...this.#scope(), request_id: requestId });
    return originalSend(requestId,this.#end.signal,(cursor,signal)=>this.#client.result({...target(),...optional({cursor})},{signal}),signal => this.#selected ? this.windows({signal}) : this.#sendUpdates(signal),options=>this.#client.cancelSend(target(),options));
  }

  async *#sendUpdates(signal: AbortSignal) {
    for await (const event of this.observe({ signal })) {
      if (event.kind === "closed") throw new ConversationClosedError();
      if (event.kind === "snapshot" || event.kind === "reset" || event.kind === "state") yield event;
    }
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

function dismissedReview(error:unknown):boolean { return error instanceof PluginBridgeError && error.errorCode==="PLUGIN_CONFIRMATION_REJECTED" && typeof error.details==="object" && error.details!==null && "review" in error.details && error.details.review==="dismissed"; }

function observationPause(signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const cancel = () => { clearTimeout(timer); reject(signal?.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", cancel); resolve(); }, 250);
    signal?.addEventListener("abort", cancel, { once: true });
  });
}
