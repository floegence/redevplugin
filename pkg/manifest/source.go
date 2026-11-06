package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/floegence/redevplugin/v3/internal/canonicaljson"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
)

// SourceSchemaVersion identifies author input, never an installable package.
const SourceSchemaVersion = "redevplugin.source.v1"

// CompileSource generates the package manifest before bindings, build and hashing.
// Identity is provided by the publishing context, never by the source document.
// All other fields retain their exact authored presence and array order.
func CompileSource(raw []byte, identity pluginidentity.Identity) (Manifest, []byte, error) {
	canonical, err := canonicaljson.CanonicalJSON(raw)
	if err != nil {
		return Manifest{}, nil, err
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(canonical, &doc); err != nil {
		return Manifest{}, nil, err
	}
	var schema string
	if err = json.Unmarshal(doc["schema_version"], &schema); err != nil || schema != SourceSchemaVersion {
		return Manifest{}, nil, errors.New("expected redevplugin.source.v1 author manifest")
	}
	var plugin map[string]json.RawMessage
	if err = json.Unmarshal(doc["plugin"], &plugin); err != nil || plugin == nil {
		return Manifest{}, nil, errors.New("source plugin must be an object")
	}
	for key := range plugin {
		switch key {
		case "slug", "display_name", "version":
		default:
			return Manifest{}, nil, errors.New("source plugin accepts only slug, display_name and version")
		}
	}
	var slug string
	if err = json.Unmarshal(plugin["slug"], &slug); err != nil {
		return Manifest{}, nil, errors.New("plugin.slug is required")
	}
	if err = pluginidentity.ValidateSlug(slug); err != nil {
		return Manifest{}, nil, err
	}
	publisher := map[string]json.RawMessage{}
	if value, exists := doc["publisher"]; exists {
		if err = json.Unmarshal(value, &publisher); err != nil || publisher == nil {
			return Manifest{}, nil, errors.New("source publisher must be an object")
		}
	}
	for key := range publisher {
		if key != "display_name" {
			return Manifest{}, nil, errors.New("source publisher accepts display_name only; identity is generated")
		}
	}
	if identity.PluginID == "" && identity.PublisherID == "" {
		identity = pluginidentity.Identity{PublisherID: "local.generated", PluginID: slug}
	}
	if identity.PluginID == "" || identity.PublisherID == "" {
		return Manifest{}, nil, errors.New("complete generated identity is required")
	}
	// The only supported publication namespace is the verified GitHub repository.
	if identity.PublisherID != "local.generated" || identity.PluginID != slug {
		expectedSuffix := "." + slug
		if !bytes.HasSuffix([]byte(identity.PluginID), []byte(expectedSuffix)) {
			return Manifest{}, nil, errors.New("generated identity does not match plugin.slug")
		}
		if err = pluginidentity.Validate(identity); err != nil {
			return Manifest{}, nil, err
		}
	}
	delete(plugin, "slug")
	plugin["plugin_id"], _ = json.Marshal(identity.PluginID)
	publisher["publisher_id"], _ = json.Marshal(identity.PublisherID)
	doc["schema_version"], _ = json.Marshal(SchemaVersionV9)
	doc["plugin"], _ = json.Marshal(plugin)
	doc["publisher"], _ = json.Marshal(publisher)
	built, err := json.Marshal(doc)
	if err != nil {
		return Manifest{}, nil, err
	}
	return DecodeCanonical(bytes.NewReader(built))
}

// DecodeAuthorCanonical accepts author source or a complete package manifest for
// binding generation and local inspection. Package admission uses DecodeCanonical.
func DecodeAuthorCanonical(r io.Reader) (Manifest, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return Manifest{}, nil, err
	}
	var header struct {
		Schema string `json:"schema_version"`
	}
	if err = json.Unmarshal(raw, &header); err != nil {
		return Manifest{}, nil, err
	}
	if header.Schema == SourceSchemaVersion {
		return CompileSource(raw, pluginidentity.Identity{})
	}
	return DecodeCanonical(bytes.NewReader(raw))
}

// AuthorSource creates editable author input from a validated package manifest.
// It removes generated identifiers without changing unrelated declarations.
func AuthorSource(raw []byte, slug string) ([]byte, error) {
	if err := pluginidentity.ValidateSlug(slug); err != nil {
		return nil, err
	}
	_, canonical, err := DecodeCanonical(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(canonical, &doc); err != nil {
		return nil, err
	}
	var plugin, publisher map[string]json.RawMessage
	if err = json.Unmarshal(doc["plugin"], &plugin); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(doc["publisher"], &publisher); err != nil {
		return nil, err
	}
	delete(plugin, "plugin_id")
	delete(publisher, "publisher_id")
	plugin["slug"], _ = json.Marshal(slug)
	doc["schema_version"], _ = json.Marshal(SourceSchemaVersion)
	doc["plugin"], _ = json.Marshal(plugin)
	doc["publisher"], _ = json.Marshal(publisher)
	source, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if _, _, err = CompileSource(source, pluginidentity.Identity{}); err != nil {
		return nil, err
	}
	return canonicaljson.CanonicalJSON(source)
}
