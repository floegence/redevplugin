package plugindata

import (
	"fmt"

	"github.com/floegence/redevplugin/pkg/manifest"
	settingsdomain "github.com/floegence/redevplugin/pkg/settings"
)

func ShapeFromManifest(value manifest.Manifest) (Shape, error) {
	settingsSchema, err := settingsdomain.CanonicalSchema(value.Settings)
	if err != nil {
		return Shape{}, err
	}
	shape := Shape{
		PublisherID: value.Publisher.PublisherID,
		PluginID:    value.PluginID(),
		Settings:    settingsSchema,
	}
	if value.Storage != nil {
		shape.Namespaces = make([]Namespace, 0, len(value.Storage.Stores))
		for _, store := range value.Storage.Stores {
			quotaFiles := manifest.DefaultStoreQuotaFiles
			if store.QuotaFiles != nil {
				quotaFiles = *store.QuotaFiles
			}
			shape.Namespaces = append(shape.Namespaces, Namespace{
				ID:            store.StoreID,
				Kind:          NamespaceKind(store.Kind),
				Scope:         store.Scope,
				SchemaVersion: store.SchemaVersion,
				QuotaBytes:    store.QuotaBytes,
				QuotaFiles:    quotaFiles,
			})
		}
	}
	normalized, err := normalizeShape(shape)
	if err != nil {
		return Shape{}, fmt.Errorf("derive plugin data shape: %w", err)
	}
	return normalized, nil
}
