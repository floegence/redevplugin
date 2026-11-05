export { repositoryIndexJSONSchema } from "./repository-index.gen.js";

export const repositoryIndexSchemaVersion = "redevplugin.repository-index.v1" as const;

export type RepositoryIndexRelease = {
  tag_template: string;
  package_asset_template: string;
};

export type RepositoryIndexPlugin = {
  plugin_id: string;
  path: string;
  manifest: string;
  release: RepositoryIndexRelease;
};

export type RepositoryIndexTarget = {
  ecosystem: "redevplugin";
  host: string;
  plugins: RepositoryIndexPlugin[];
};

export type RepositoryIndex = {
  $schema?: string;
  schema_version: typeof repositoryIndexSchemaVersion;
  targets: RepositoryIndexTarget[];
};

const releaseTemplate = /^[A-Za-z0-9._+@-]+(?:\{version\}[A-Za-z0-9._+@-]*)?$/;
const tagTemplate = /^[a-z0-9]+(?:-[a-z0-9]+)*-v\{version\}$/;
const stableVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

/** Match a whole release tag against its plugin namespace. */
export function repositoryIndexVersionFromTag(template: string, tag: string): string | undefined {
  if (template.length > 255 || tag.length > 255 || !tagTemplate.test(template)) return undefined;
  const [prefix, suffix] = template.split("{version}");
  if (!tag.startsWith(prefix) || !tag.endsWith(suffix) || tag.length < prefix.length + suffix.length) return undefined;
  const version = tag.slice(prefix.length, tag.length - suffix.length);
  return stableVersion.test(version) ? version : undefined;
}

export function repositoryIndexRenderTemplate(template: string, version: string): string {
  if (template.length > 255 || !releaseTemplate.test(template) || !stableVersion.test(version)) throw new Error("Invalid repository release template or version");
  const result = template.replace("{version}", version);
  if (result.length > 255) throw new Error("Rendered repository release name exceeds 255 bytes");
  return result;
}
