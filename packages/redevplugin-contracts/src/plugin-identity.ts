/** Source-derived identity is valid only against an independently observed repository. */
export function githubPluginIdentity(repositoryID: number, slug: string): { publisher_id: string; plugin_id: string } {
  if (!Number.isSafeInteger(repositoryID) || repositoryID <= 0) throw new Error("Repository ID must be a positive safe integer");
  if (slug.length > 80 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) throw new Error("Invalid plugin slug");
  const publisher_id = `github.repo.${repositoryID}`;
  return { publisher_id, plugin_id: `${publisher_id}.${slug}` };
}

export function validateGitHubPluginIdentity(repositoryID: number, publisherID: string, pluginID: string): void {
  const prefix = githubPluginIdentity(repositoryID, "plugin").publisher_id;
  if (!pluginID.startsWith(prefix + ".")) throw new Error("Plugin ID does not belong to the observed GitHub repository");
  const identity = githubPluginIdentity(repositoryID, pluginID.slice(prefix.length + 1));
  if (publisherID !== identity.publisher_id || pluginID !== identity.plugin_id) throw new Error("Publisher and plugin identity do not match the observed GitHub repository");
}

export { repositoryIdentityJSONSchema } from "./repository-index.gen.js";
