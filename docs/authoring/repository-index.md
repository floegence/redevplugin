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
      "plugin_id": "github.repo.123456.weather",
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
redevplugin repository identity plugins/weather weather
redevplugin scaffold repository-index . redeven \
  --project plugins/weather --manifest manifest.json \
  --tag-template 'weather-v{version}' \
  --package-asset-template plugin.redevplugin
redevplugin repository validate .
npm --prefix plugins/weather run build
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
plugin, release, asset, content digest, and owner. The downloader rechecks the
selected repository, tag commit, release and asset after downloading; developers
do not need to enable immutable GitHub Releases. Repository identity prevents
a different source with the same plugin ID from silently taking over updates.

## Repository-derived identity

For GitHub distribution, authors choose only a plugin slug (1–80 lowercase ASCII
letters, digits, and single separating hyphens). `repository identity` obtains the
numeric repository ID from GitHub using the enclosing Git origin, or an explicit
`--repository https://github.com/owner/repo`. `GITHUB_TOKEN` is optional for public
repositories. Neither publisher registration nor a signing key is involved.

The tool writes `publisher_id = github.repo.<repository-id>` and
`plugin_id = github.repo.<repository-id>.<slug>` to the source manifest. Run it
before building and packaging, then generate the index. Existing index entries can
be replaced explicitly with `scaffold repository-index ... --replace`. Never
rewrite identities in packaged bytes or in a market's package projection.

The market and Host each validate both IDs against the independently observed
repository ID. Repository choices and release downloads also reject foreign
namespaces before offering or fetching a package. An author-supplied prefix
alone proves nothing. Forks and new
repositories get their own namespace; renaming or transferring the same repository
preserves its numeric identity. This identifies a repository, not a person or a
promise about its contents. Official and community repositories use identical
rules, while official presentation is selected by the configured source repository.

Local, uploaded, and direct HTTPS packages retain their actual source category,
even if their manifest declares a GitHub-shaped ID. Those declarations never turn
into verified GitHub provenance. Existing source-change confirmation, immutable
same-version content checks, sandboxing, and runtime permissions still apply.
