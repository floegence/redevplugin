package httpadapter

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestHandlerRetainedRecoveryInspectCommitAndReadback(t *testing.T) {
	h := newHTTPTestHost(t)
	handler := mustNewHandler(t, h, allowHTTPTestGuard())
	pkg := buildHTTPStorageFixturePackage(t)
	source := postLocalImport[registry.PluginRecord](t, handler, "recovery_source", pkg)
	target := postLocalImport[registry.PluginRecord](t, handler, "recovery_target", pkg)
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/uninstall", map[string]any{"plugin_instance_id": source.PluginInstanceID, "expected_management_revision": source.ManagementRevision, "delete_data": false})
	postJSON[registry.PluginRecord](t, handler, "/_redevplugin/api/plugins/disable", map[string]any{"plugin_instance_id": target.PluginInstanceID, "expected_management_revision": target.ManagementRevision})
	candidates := postJSON[struct {
		RetainedData []plugindata.Binding `json:"retained_data"`
	}](t, handler, "/_redevplugin/api/plugins/retained-data/query", map[string]any{"target_plugin_instance_id": target.PluginInstanceID})
	if len(candidates.RetainedData) != 1 || candidates.RetainedData[0].PluginInstanceID != source.PluginInstanceID {
		t.Fatalf("recovery candidates=%#v", candidates)
	}
	inspection := postJSON[host.RetainedRecoveryInspection](t, handler, "/_redevplugin/api/plugins/retained-data/recovery/inspect", map[string]any{"source_plugin_instance_id": source.PluginInstanceID, "target_plugin_instance_id": target.PluginInstanceID})
	encoded, err := json.Marshal(inspection.Plan)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	fields["owner_env_hash"] = "forged"
	postJSONError(t, handler, "/_redevplugin/api/plugins/retained-data/recovery/commit", map[string]any{"plan": fields, "plan_hash": inspection.PlanHash}, http.StatusBadRequest)
	request := map[string]any{"plan": inspection.Plan, "plan_hash": inspection.PlanHash}
	pending := postJSON[host.RetainedRecoveryStatus](t, handler, "/_redevplugin/api/plugins/retained-data/recovery/status", request)
	if pending.State != "pending" {
		t.Fatalf("pending=%#v", pending)
	}
	result := postJSON[plugindata.RetainedRecoveryResult](t, handler, "/_redevplugin/api/plugins/retained-data/recovery/commit", request)
	if result.Active.GenerationID != inspection.Plan.Source.GenerationID || result.Retained.GenerationID != inspection.Plan.Target.GenerationID {
		t.Fatalf("result=%#v", result)
	}
	applied := postJSON[host.RetainedRecoveryStatus](t, handler, "/_redevplugin/api/plugins/retained-data/recovery/status", request)
	if applied.State != "applied" || applied.Result == nil {
		t.Fatalf("applied=%#v", applied)
	}
	postJSONError(t, handler, "/_redevplugin/api/plugins/retained-data/recovery/commit", request, http.StatusConflict)
	postJSONError(t, handler, "/_redevplugin/api/plugins/retained-data/recovery/inspect", map[string]any{"source_plugin_instance_id": source.PluginInstanceID, "target_plugin_instance_id": target.PluginInstanceID, "owner_env_hash": "foreign"}, http.StatusBadRequest)
}
