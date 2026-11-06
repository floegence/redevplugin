package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/authorapi"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
)

func TestPublicationGenerationPreservesSourceAndSeparatesForks(t *testing.T) {
	root := t.TempDir()
	if _, err := createPluginTemplate("mind-map", "Mind Map", root, "web"); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "manifest.json")
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{42, 43} {
		identity, err := pluginidentity.GitHub(id, "mind-map")
		if err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(root, "generated")
		if err = authorapi.WriteIdentity(source, output, false, identity); err != nil {
			t.Fatal(err)
		}
		if err = authorapi.WriteIdentity(source, output, true, identity); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(output, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		m, _, err := manifest.DecodeCanonical(bytes.NewReader(raw))
		if err != nil || m.PluginID() != identity.PluginID || m.Publisher.PublisherID != identity.PublisherID {
			t.Fatal(m, err)
		}
		after, _ := os.ReadFile(source)
		if !bytes.Equal(before, after) {
			t.Fatal("publication changed author input")
		}
	}
	// Local generation is offline and clears any previously generated release identity.
	if err = generateAuthorAPI(source, filepath.Join(root, "generated"), false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "generated/manifest.json"))
	m, _, err := manifest.DecodeCanonical(bytes.NewReader(raw))
	if err != nil || m.PluginID() != "mind-map" || m.Publisher.PublisherID != "local.generated" {
		t.Fatal(m, err)
	}
}

func TestPublicationRequiresRepositoryOnlyForRelease(t *testing.T) {
	root := t.TempDir()
	if _, err := createPluginTemplate("example", "Example", root, "web"); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "manifest.json")
	if _, err := authorPublication(context.Background(), input, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := authorPublication(context.Background(), input, "", true); err == nil {
		t.Fatal("release accepted without repository")
	}
	if _, err := authorPublication(context.Background(), input, "https://github.com/example/plugin", false); err == nil {
		t.Fatal("ignored repository without release")
	}
	if err := run(context.Background(), []string{"repository", "identity", root, "example"}); err == nil {
		t.Fatal("retired source-mutating identity command accepted")
	}
}

func TestPublicationGenerationReadsTheRequestedManifest(t *testing.T) {
	root := t.TempDir()
	if _, err := createPluginTemplate("example", "Example", root, "web"); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "custom-source.json")
	if err := os.Rename(filepath.Join(root, "manifest.json"), input); err != nil {
		t.Fatal(err)
	}
	// A malformed repository is rejected locally after reading the explicit input,
	// so this regression requires neither Git nor a network connection.
	err := runAuthorGenerate(context.Background(), []string{input, filepath.Join(root, "generated"), "--release", "--repository", "invalid"})
	if err == nil || os.IsNotExist(err) || !strings.Contains(err.Error(), "github") {
		t.Fatalf("expected repository validation after reading custom source, got %v", err)
	}
}
