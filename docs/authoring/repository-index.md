# Repository discovery

A repository can advertise multiple ReDevPlugin packages to host-specific
catalogs without changing its existing layout for other ecosystems. Add the
GitHub topic `redevplugin` and create `.redevplugin/index.json` at the root.
For Redeven, also use the `redeven-plugin` topic and set `host` to `redeven`.
The host value is a discovery declaration, not proof of compatibility or trust.

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
        "package_asset_template": "weather-{version}.redevplugin",
        "release_ref_asset_template": "weather-{version}.release-ref.json"
      }
    }]
  }]
}
```

Use `.` for a plugin at the repository root. Paths are repository-relative,
use `/`, and cannot traverse or contain symbolic links. Templates contain one
`{version}` and match complete names. A catalog may apply further restrictions,
including stable versions, review, trusted publishers and immutable releases.
Presentation and permissions remain in the verified package, not this index.

`redevplugin scaffold repository-index <root> <host>` creates an initial entry
from a root manifest; review the host and asset names before publishing.
`redevplugin repository inspect <root>` checks the index and emits JSON with
per-entry policy digests. `redevplugin repository validate <root>` additionally
checks every declared manifest and its plugin ID. An enclosing index is checked
by `redevplugin check` and `doctor`. Adding a sibling entry does not change an
existing entry's policy digest.

For new GitHub-hosted third-party plugins, a useful ID convention is
`github.<owner>.<repository>.<plugin-slug>`. Freeze the chosen ID after release;
repository moves must not silently change installed identity. GitHub coordinates
and topics do not prove publisher identity or grant installation permissions.
