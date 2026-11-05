package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/floegence/redevplugin/v3/pkg/authoring"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/releasepublisher"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

type validateSummary struct {
	DataShapeSHA256 string `json:"data_shape_sha256,omitempty"`
	OK              bool   `json:"ok"`
	Kind            string `json:"kind"`
	PluginID        string `json:"plugin_id"`
	Version         string `json:"version"`
	PackageHash     string `json:"package_hash,omitempty"`
	ManifestHash    string `json:"manifest_hash,omitempty"`
	EntriesHash     string `json:"entries_hash,omitempty"`
}

type lifecycleSummary struct {
	OK                 bool                 `json:"ok"`
	Action             string               `json:"action"`
	PluginInstanceID   string               `json:"plugin_instance_id"`
	PluginID           string               `json:"plugin_id"`
	Version            string               `json:"version"`
	EnableState        registry.EnableState `json:"enable_state"`
	PolicyRevision     uint64               `json:"policy_revision"`
	ManagementRevision uint64               `json:"management_revision"`
	RevokeEpoch        uint64               `json:"revoke_epoch"`
}

type platformVersionSummary struct {
	PlatformVersion string `json:"platform_version"`
	PluginAPI       uint16 `json:"plugin_api"`
	InternalWire    uint16 `json:"internal_wire"`
}

type presentationIconExtractionSummary struct {
	OK               bool                                        `json:"ok"`
	Phase            string                                      `json:"phase"`
	Output           string                                      `json:"output"`
	IconOutput       string                                      `json:"icon_output"`
	PresentationIcon releasepublisher.PresentationIconEvidenceV1 `json:"presentation_icon"`
	VerifierVersion  string                                      `json:"verifier_version"`
}

type dataInspectSummary struct {
	OK               bool                      `json:"ok"`
	StateRoot        string                    `json:"state_root"`
	PluginDataRoot   string                    `json:"plugin_data_root"`
	PluginInstanceID string                    `json:"plugin_instance_id,omitempty"`
	BindingCount     int                       `json:"binding_count"`
	ObjectCount      int                       `json:"object_count"`
	NamespaceCount   int                       `json:"namespace_count"`
	TotalUsageBytes  int64                     `json:"total_usage_bytes"`
	TotalUsageFiles  int64                     `json:"total_usage_files"`
	Bindings         []plugindata.Binding      `json:"bindings"`
	Objects          []plugindata.Object       `json:"objects"`
	Namespaces       []storage.NamespaceRecord `json:"namespaces"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "redevplugin: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	ctx = cliContext(ctx)
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "repository":
		return runRepositoryIndex(args[1:])
	case "runtime":
		return runAuthorRuntimePrepare(ctx, args[1:])
	case "check", "doctor":
		if len(args) != 2 {
			return usage()
		}
		return runAuthorCheck(ctx, args[1], args[0] == "doctor")
	case "generate":
		if len(args) != 3 && (len(args) != 4 || args[3] != "--check") {
			return usage()
		}
		return generateAuthorAPI(args[1], args[2], len(args) == 4)
	case "validate":
		if len(args) != 2 {
			return usage()
		}
		return validate(ctx, args[1])
	case "package":
		if len(args) != 3 {
			return usage()
		}
		return buildPackage(ctx, args[1], args[2])
	case "dev":
		return runAuthorDev(ctx, args[1:])
	case "test":
		return runAuthorTest(ctx, args[1:])
	case "init", "scaffold":
		if args[0] == "scaffold" && len(args) >= 2 && args[1] == "repository-index" {
			return scaffoldRepositoryIndex(args[2:])
		}
		if len(args) != 4 && (len(args) != 6 || args[4] != "--template") {
			return usage()
		}
		template := "web"
		if args[0] == "scaffold" {
			template = "worker"
		}
		if len(args) == 6 {
			template = args[5]
		}
		summary, err := createPluginTemplate(args[1], args[2], args[3], template)
		if err != nil {
			return err
		}
		return writeJSON(summary)
	case "version":
		return writeJSON(platformVersionSummary{PlatformVersion: version.CurrentPlatformVersion(), PluginAPI: 1, InternalWire: 1})
	case "release":
		return runRelease(ctx, args[1:])
	case "inspect-data":
		if len(args) != 2 && len(args) != 3 {
			return usage()
		}
		pluginInstanceID := ""
		if len(args) == 3 {
			pluginInstanceID = args[2]
		}
		return inspectData(ctx, args[1], pluginInstanceID)
	case "install-local":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "install-local", args[1])
	case "dev-install":
		if len(args) != 3 {
			return usage()
		}
		return devInstall(ctx, args[1], args[2])
	case "dev-enable":
		if len(args) != 2 {
			return usage()
		}
		return devEnable(ctx, args[1])
	case "dev-open":
		if len(args) != 3 {
			return usage()
		}
		return devOpen(ctx, args[1], args[2])
	case "dev-secret-bind":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		return devSecretBind(ctx, args[1], args[2], optionalSecretScope(args))
	case "dev-secret-test":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		return devSecretTest(ctx, args[1], args[2], optionalSecretScope(args))
	case "dev-secret-delete":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		return devSecretDelete(ctx, args[1], args[2], optionalSecretScope(args))
	case "dev-permission-grant":
		if len(args) != 3 {
			return usage()
		}
		return devPermissionGrant(ctx, args[1], args[2])
	case "dev-permission-revoke":
		if len(args) != 3 && len(args) != 4 {
			return usage()
		}
		reason := "dev-cli"
		if len(args) == 4 {
			reason = args[3]
		}
		return devPermissionRevoke(ctx, args[1], args[2], reason)
	case "dev-permission-list":
		if len(args) != 2 && len(args) != 3 {
			return usage()
		}
		activeOnly := false
		if len(args) == 3 {
			if args[2] != "--active-only" {
				return usage()
			}
			activeOnly = true
		}
		return devPermissionList(ctx, args[1], activeOnly)
	case "dev-export-data":
		if len(args) != 2 {
			return usage()
		}
		return devExportData(ctx, args[1])
	case "dev-import-data":
		if len(args) != 3 {
			return usage()
		}
		return devImportData(ctx, args[1], args[2])
	case "dev-delete-export":
		if len(args) != 3 {
			return usage()
		}
		return devDeleteExport(ctx, args[1], args[2])
	case "dev-disable":
		if len(args) != 2 {
			return usage()
		}
		return devDisable(ctx, args[1])
	case "dev-uninstall":
		if len(args) != 2 {
			return usage()
		}
		return devUninstall(ctx, args[1])
	case "dev-status":
		if len(args) != 2 {
			return usage()
		}
		return devStatus(args[1])
	case "examples-server":
		if len(args) != 3 {
			return usage()
		}
		return examplesServer(ctx, args[1], args[2])
	case "enable":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "enable", args[1])
	case "disable":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "disable", args[1])
	case "uninstall":
		if len(args) != 2 {
			return usage()
		}
		return lifecycleHarness(ctx, "uninstall", args[1])
	default:
		return usage()
	}
}

func inspectData(ctx context.Context, root string, pluginInstanceID string) error {
	root, err := normalizeDevStateRoot(root)
	if err != nil {
		return err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	harness, err := newDevHarness(ctx, root, pluginpkg.NewMemoryAssetStore())
	if err != nil {
		return err
	}
	defer harness.Close()
	inspection, err := harness.host.InspectPluginData(ctx, host.InspectPluginDataRequest{PluginInstanceID: pluginInstanceID})
	if err != nil {
		return err
	}
	objects := make([]plugindata.Object, len(inspection.Objects))
	for index := range inspection.Objects {
		objects[index] = inspection.Objects[index].Object
	}
	return writeJSON(dataInspectSummary{
		OK:               true,
		StateRoot:        root,
		PluginDataRoot:   filepath.Join(root, devPluginDataDir),
		PluginInstanceID: pluginInstanceID,
		BindingCount:     len(inspection.Bindings),
		ObjectCount:      len(objects),
		NamespaceCount:   len(inspection.Namespaces),
		TotalUsageBytes:  inspection.TotalUsageBytes,
		TotalUsageFiles:  inspection.TotalUsageFiles,
		Bindings:         inspection.Bindings,
		Objects:          objects,
		Namespaces:       inspection.Namespaces,
	})
}

func validate(ctx context.Context, filename string) error {
	if strings.HasSuffix(filename, ".redevplugin") || strings.HasSuffix(filename, ".zip") {
		pkg, err := pluginpkg.ReadFile(ctx, filename, pluginpkg.DefaultReadLimits())
		if err != nil {
			return err
		}
		shape, err := plugindata.ShapeFromManifest(pkg.Manifest)
		if err != nil {
			return err
		}
		shapeHash, err := plugindata.HashShape(shape)
		if err != nil {
			return err
		}
		return writeJSON(validateSummary{
			DataShapeSHA256: shapeHash,
			OK:              true,
			Kind:            "package",
			PluginID:        pkg.Manifest.PluginID(),
			Version:         pkg.Manifest.Version(),
			PackageHash:     pkg.PackageHash,
			ManifestHash:    pkg.ManifestHash,
			EntriesHash:     pkg.EntriesHash,
		})
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	shape, err := plugindata.ShapeFromManifest(decoded)
	if err != nil {
		return err
	}
	shapeHash, err := plugindata.HashShape(shape)
	if err != nil {
		return err
	}
	return writeJSON(validateSummary{
		DataShapeSHA256: shapeHash,
		OK:              true,
		Kind:            "manifest",
		PluginID:        decoded.PluginID(),
		Version:         decoded.Version(),
	})
}

func buildPackage(ctx context.Context, srcDir string, outFile string) error {
	if outDir := filepath.Dir(outFile); outDir != "." {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(ctx, srcDir, &buf, pluginpkg.DefaultReadLimits())
	if err != nil {
		return err
	}
	if err := os.WriteFile(outFile, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return writeJSON(validateSummary{
		OK:           true,
		Kind:         "package",
		PluginID:     pkg.Manifest.PluginID(),
		Version:      pkg.Manifest.Version(),
		PackageHash:  pkg.PackageHash,
		ManifestHash: pkg.ManifestHash,
		EntriesHash:  pkg.EntriesHash,
	})
}

func optionalSecretScope(args []string) string {
	if len(args) == 4 {
		return args[3]
	}
	return "user"
}

func writeJSON(v any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func writeBytesFile(filename string, data []byte, perm os.FileMode) error {
	if outDir := filepath.Dir(filename); outDir != "." {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filename, data, perm); err != nil {
		return err
	}
	return os.Chmod(filename, perm)
}

func usage() error {
	return fmt.Errorf("usage: redevplugin repository inspect|validate <repository-root> | redevplugin scaffold repository-index <repository-root> <host> | redevplugin check <source-dir> | redevplugin doctor <source-dir> | redevplugin init <plugin-id> <display-name> <out-dir> [--template web|data|worker|monitor|files] | redevplugin generate <manifest.json> <output-dir> [--check] | redevplugin runtime prepare <new-directory> | redevplugin dev <source-dir> [--state <directory>] [--manual] [--runtime <path> --runtime-sha256 <digest>] | redevplugin test <source-dir> [--runtime <path> --runtime-sha256 <digest> --surface <id> --method <name> --params <json>] | redevplugin validate <manifest.json|package.redevplugin> | redevplugin scaffold <plugin-id> <display-name> <out-dir> | redevplugin package <dir> <out.redevplugin>| redevplugin release inspect <package.redevplugin> [capability-contract.json ...] | redevplugin release extract-presentation-icon <package.redevplugin> <out-file> [capability-contract.json ...] | redevplugin inspect-data <state-root> [plugin-instance-id] | redevplugin install-local <package>| redevplugin dev-install <state-root> <package> | redevplugin dev-enable <state-root> | redevplugin dev-open <state-root> <surface-id> | redevplugin dev-secret-bind <state-root> <secret-ref> [user|environment] | redevplugin dev-secret-test <state-root> <secret-ref> [user|environment] | redevplugin dev-secret-delete <state-root> <secret-ref> | redevplugin dev-permission-grant <state-root> <permission-id> | redevplugin dev-permission-revoke <state-root> <permission-id> [reason] | redevplugin dev-permission-list <state-root> [--active-only] | redevplugin dev-export-data <state-root> | redevplugin dev-import-data <state-root> <bundle-ref> | redevplugin dev-delete-export <state-root> | redevplugin dev-disable <state-root> | redevplugin dev-uninstall <state-root> | redevplugin dev-status <state-root> | redevplugin examples-server <state-root> <runtime-path> | redevplugin enable <package> | redevplugin disable <package> | redevplugin uninstall <package> | redevplugin version")
}

func lifecycleHarness(ctx context.Context, action string, packageFile string) error {
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "redevplugin-lifecycle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	config, err := newEphemeralCLIAdapters(root)
	if err != nil {
		return err
	}
	h, err := host.Open(ctx, config)
	if err != nil {
		return err
	}
	defer h.Close()
	pluginInstanceID, err := newCLIPluginInstanceID()
	if err != nil {
		return err
	}
	record, err := host.ImportLocalPackageBytes(ctx, h, pluginInstanceID, data)
	if err != nil {
		return err
	}
	switch action {
	case "install-local":
		return writeLifecycle(action, record)
	case "enable":
		record, err = h.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
	case "disable":
		record, err = h.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
		if err == nil {
			record, err = h.DisablePlugin(ctx, host.DisableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, Reason: "cli"})
		}
	case "uninstall":
		record, err = h.UninstallPlugin(ctx, host.UninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, DeleteData: true})
	}
	if err != nil {
		return err
	}
	return writeLifecycle(action, record)
}

func newCLIPluginInstanceID() (string, error) {
	raw := make([]byte, 18)
	if _, err := crand.Read(raw); err != nil {
		return "", err
	}
	return "plugini_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func writeLifecycle(action string, record registry.PluginRecord) error {
	return writeJSON(lifecycleSummary{
		OK:                 true,
		Action:             action,
		PluginInstanceID:   record.PluginInstanceID,
		PluginID:           record.PluginID,
		Version:            record.Version,
		EnableState:        record.EnableState,
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
	})
}

func cliContext(ctx context.Context) context.Context {
	return sessionctx.WithContext(ctx, sessionctx.Context{
		OwnerSessionHash:     "cli_owner_session",
		OwnerUserHash:        "cli_owner_user",
		OwnerEnvHash:         "cli_owner_environment",
		SessionChannelIDHash: "cli_session_channel",
	})
}

func newEphemeralCLIAdapters(stateRoot string) (host.Config, error) {
	events := observability.NewMemoryStore()
	connectivityBroker := connectivity.NewMemoryBroker()
	return host.Config{
		StateRoot: stateRoot,
		Core: host.CoreAdapters{
			Policy:        staticPolicyAdapter{},
			Authorization: staticAuthorizationAdapter{},
			Audit:         events,
			SecurityAudit: events,
			Diagnostics:   events,
			Assets:        pluginpkg.NewMemoryAssetStore(),
		},
		Connectivity: &host.ConnectivityModule{
			Broker:          connectivityBroker,
			NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{}),
		},
		Secrets: &host.SecretsModule{Store: secrets.NewMemoryStore()},
	}, nil
}

type staticPolicyAdapter struct{}

type staticAuthorizationAdapter struct{}

func (staticAuthorizationAdapter) Authorize(_ context.Context, req host.AuthorizationRequest) error {
	if !req.Session.Valid() || !req.Action.Valid() || !req.Target.Kind.Valid() || req.Target.Kind != req.Action.Resource() {
		return host.ErrActionDenied
	}
	return nil
}

func (staticPolicyAdapter) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, nil
}

type scaffoldSummary = authoring.TemplateResult

func createPluginTemplate(pluginID, displayName, directory, template string) (scaffoldSummary, error) {
	return authoring.Init(pluginID, displayName, directory, template)
}
func createPluginScaffold(pluginID, displayName, directory string) (scaffoldSummary, error) {
	return authoring.Init(pluginID, displayName, directory, "worker")
}
