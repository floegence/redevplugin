import {
  type PluginBridgeClient,
  type PluginOperation,
} from "@floegence/redevplugin-ui/plugin";

import {
  ExampleDocumentsClient,
  isExampleDocumentsBusinessError,
  type DocumentsArchiveResponse,
} from "./capabilities/example.documents/v1.0.0/example.documents.v1.client.js";

export type DocumentsConsumerResult = {
  document_count: number;
  archive: PluginOperation<DocumentsArchiveResponse>;
};

export async function runDocumentsConsumer(
  bridge: PluginBridgeClient,
  writeLine: (line: string) => void,
): Promise<DocumentsConsumerResult> {
  const client = new ExampleDocumentsClient(bridge);
  let documentCount = 0;
  try {
    const listed = await client.list({ workspace_id: "workspace-1" });
    documentCount = listed.documents.length;
  } catch (error) {
    if (!isExampleDocumentsBusinessError(error)) throw error;
    writeLine(`missing document: ${error.details.business_error_details.document_id}`);
  }

  const archive = await client.archive({ document_id: "doc-1" });
  if (!archive.data.accepted) await archive.cancel("archive was not accepted");

  const watch = await client.watch({ workspace_id: "workspace-1" });
  if (watch.data.watching) {
    for await (const event of watch) {
      writeLine(`${event.data.change}: ${event.data.document_id}`);
    }
  }
  return { document_count: documentCount, archive };
}
