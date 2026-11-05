# Repository discovery

Add the GitHub topic `redevplugin` and a `.redevplugin/index.json` on the default
branch. `redeven-plugin` is an optional additional topic. A host target is a
routing declaration. Authors need no registration, approval, signing key,
release-reference attachment, or publisher verification.

```json
{
  "schema_version": "redevplugin.repository-index.v1",
  "targets": [{
    "ecosystem": "redevplugin",
    "host": "redeven",
    "plugins": [{
      "plugin_id": "github.alice.weather-tools.weather",
      "path": "plugins/weather",
      "manifest": "manifest.json",
      "release": {
        "tag_template": "weather-v{version}",
        "package_asset_template": "plugin.redevplugin"
      }
    }]
  }]
}
```

Each plugin owns a distinct `<release-key>-v{version}` namespace. Versions are
strict stable SemVer. Drafts and prereleases are excluded. Version comparison
uses SemVer, never publication time or the repository-wide latest Release.
Every Release contains one matching ordinary `.redevplugin` package. Asset names
can contain one `{version}` or be fixed; separate Releases can reuse the same
asset name. Never replace a published version's package with different content.

Use `.` for a root project. Paths are repository-relative and cannot traverse
or contain symbolic links. Plugin identity, author presentation, and capabilities
come from validated package bytes. Official and community are presentation
categories and share the same installation and update contracts.

```sh
redevplugin scaffold repository-index . redeven \
  --project plugins/weather --manifest manifest.json \
  --tag-template 'weather-v{version}' \
  --package-asset-template plugin.redevplugin
redevplugin repository validate .
redevplugin package plugins/weather/dist plugin.redevplugin
redevplugin release inspect plugin.redevplugin
```

Scaffolding appends to the existing index under an operating-system file lock.
Identical calls are no-ops; changing an existing entry requires `--replace`.
The complete proposed index and all declared manifests are validated before
atomic replacement. Moving a project can be repaired with `--replace`.
`repository inspect` emits per-entry content digests; unrelated entries do not
change an existing entry's digest. `check` and `doctor` validate an enclosing index.

A repository can contain multiple projects and ecosystems. Hosts must select an
explicit plugin when more than one matches. Installation binds the chosen
plugin, release, asset, content digest, and owner. Repository identity prevents
a different source with the same plugin ID from silently taking over updates.
