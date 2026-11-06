# Repository discovery

Add the GitHub topic `redevplugin` and a `.redevplugin/index.json` on the default
branch. `redeven-plugin` is an optional additional topic. A host target is a
routing declaration. Authors need no registration, approval, signing key,
release-reference attachment, publisher verification, or numeric repository ID.

```json
{
  "schema_version": "redevplugin.repository-index.v1",
  "targets": [{
    "ecosystem": "redevplugin",
    "host": "redeven",
    "plugins": [{
      "slug": "weather",
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

The editable `manifest.json` uses `redevplugin.source.v1` and `plugin.slug`.
It has no `plugin_id`, `publisher_id`, or repository ID. An optional publisher
object contains only an author-owned display name. The remaining declarations
use the package manifest contract; the platform validates them with the same
parser when compiling the source. Source documents are never installable.

Each plugin owns a distinct `<release-key>-v{version}` namespace. Versions are
strict stable SemVer. Drafts and prereleases are excluded. Version comparison
uses SemVer, never publication time or the repository-wide latest Release.
Every Release contains one matching ordinary `.redevplugin` package. Asset names
can contain one `{version}` or be fixed; separate Releases can reuse an asset
name. Never replace a published version's package with different content.

Use `.` for a root project. Paths are repository-relative and cannot traverse
or contain symbolic links. Official and community are presentation categories
and share the same installation and update contracts.

```sh
redevplugin scaffold repository-index . redeven \
  --project plugins/weather --manifest manifest.json \
  --tag-template 'weather-v{version}' \
  --package-asset-template plugin.redevplugin
redevplugin repository validate .
redevplugin build plugins/weather --release
redevplugin package plugins/weather/dist plugin.redevplugin
redevplugin release inspect plugin.redevplugin
```

Scaffolding appends to the existing index under an operating-system file lock.
Identical calls are no-ops; changing an existing entry requires `--replace`.
The complete proposed index and all declared source manifests are validated
before atomic replacement. Moving a project can be repaired with `--replace`.
`repository inspect` emits per-entry content digests; unrelated entries do not
change an existing entry's digest. `check` and `doctor` validate an enclosing index.

## Generated publication identity

Authors choose only a repository-local slug (1–80 lowercase ASCII letters,
digits, and single separating hyphens). `build --release` resolves the real
GitHub repository through the enclosing Git origin. An explicit
`--repository https://github.com/owner/repo` supports exported source directories.
`GITHUB_TOKEN` is optional for public repositories. A supplied numeric ID or an
identity in source is never accepted as provenance.

Before bindings and build commands run, the platform compiles a canonical v9
package manifest with `publisher_id = github.repo.<repository-id>` and
`plugin_id = github.repo.<repository-id>.<slug>`. Generated bindings and the
compiled manifest share one identity. Build scripts copy `generated/manifest.json`
to their output; the pipeline checks exact canonical equality before packaging.
Hashing and package construction happen only after that check. The editable
source and index are never rewritten. `generate manifest.json generated --release`
provides the same preparation for custom build systems.

Local `generate`, `build`, `check`, `test`, and `dev` do not query GitHub. They
compile the slug as a local package identity under `local.generated` in the
explicit project/environment scope. A release build never changes local source
identity; a subsequent local build regenerates its own local bindings. Generated
files and build outputs are ignored source artifacts, not author inputs.

The market resolves each index slug using the independently observed repository
ID. The Host does the same for repository selection and downloads, and validates
the exact package identity against the observed source. Neither trusts a prefix
from the author or from a market listing alone. Forks and new repositories receive
their own namespace; a rename or transfer of the same repository retains its
numeric identity. This identifies a repository, not a person or trustworthy code.

A repository may contain multiple projects and ecosystems. Hosts must select one
plugin when multiple entries match. Downloads bind the selected plugin, release,
asset, content digest, and owner. The downloader rechecks repository, commit,
release and asset after downloading. Immutable GitHub Releases are not required.
Local, uploaded, and direct HTTPS packages retain their actual source category,
even if a package contains a GitHub-shaped ID. Source-change confirmation,
same-version content checks, sandboxing, and runtime permissions remain separate.
