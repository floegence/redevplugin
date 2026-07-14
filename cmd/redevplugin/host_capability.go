package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/version"
)

const hostCapabilityPinFile = "host-capability.pin.json"

type hostCapabilityBuildConfig struct {
	ContractFile             string `json:"contract_file"`
	PrivateKeyFile           string `json:"private_key_file"`
	ArtifactBaseRef          string `json:"artifact_base_ref"`
	GeneratedAt              string `json:"generated_at"`
	SourceCommit             string `json:"source_commit"`
	MinReDevPluginVersion    string `json:"min_redevplugin_version"`
	SignaturePolicyEpoch     string `json:"signature_policy_epoch"`
	SignatureRevocationEpoch string `json:"signature_revocation_epoch"`
	NoticesFile              string `json:"notices_file,omitempty"`
}

type hostCapabilitySummary struct {
	OK                bool                   `json:"ok"`
	Action            string                 `json:"action"`
	ContractID        string                 `json:"contract_id"`
	ContractVersion   string                 `json:"contract_version"`
	CapabilityID      string                 `json:"capability_id"`
	CapabilityVersion string                 `json:"capability_version"`
	Pin               capabilitycontract.Pin `json:"pin"`
	Output            string                 `json:"output,omitempty"`
}

type loadedHostCapabilityArtifact struct {
	Verified  capabilitycontract.VerifiedContract
	Bundle    capabilitycontract.Bundle
	PublicDoc signingPublicKeyFile
	PublicKey []byte
}

func runHostCapability(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "build":
		if len(args) != 3 {
			return usage()
		}
		return buildHostCapability(ctx, args[1], args[2])
	case "verify":
		if len(args) != 4 {
			return usage()
		}
		loaded, err := loadVerifiedHostCapability(args[1], args[2], args[3])
		if err != nil {
			return err
		}
		return writeJSON(hostCapabilitySummary{
			OK:                true,
			Action:            "verify",
			ContractID:        loaded.Verified.Contract.ContractID,
			ContractVersion:   loaded.Verified.Contract.ContractVersion,
			CapabilityID:      loaded.Verified.Contract.CapabilityID,
			CapabilityVersion: loaded.Verified.Contract.CapabilityVersion,
			Pin:               loaded.Verified.Pin,
			Output:            filepath.Clean(args[1]),
		})
	case "generate-client":
		if len(args) != 5 && (len(args) != 6 || args[5] != "--check") {
			return usage()
		}
		return generateHostCapabilityClient(args[1], args[2], args[3], args[4], len(args) == 6)
	default:
		return usage()
	}
}

func buildHostCapability(_ context.Context, configFile, outputRoot string) error {
	var config hostCapabilityBuildConfig
	if err := readStrictJSONFile(configFile, &config); err != nil {
		return err
	}
	configDir := filepath.Dir(configFile)
	contractFile := resolveConfigPath(configDir, config.ContractFile)
	privateKeyFile := resolveConfigPath(configDir, config.PrivateKeyFile)
	var contract capabilitycontract.Contract
	if err := readStrictJSONFile(contractFile, &contract); err != nil {
		return err
	}
	privateDoc, privateKey, err := readSigningPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}
	if privateDoc.PublisherID != "" && privateDoc.PublisherID != contract.PublisherID {
		return errors.New("host capability private key publisher_id does not match contract")
	}
	generatedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(config.GeneratedAt))
	if err != nil {
		return fmt.Errorf("generated_at must be RFC3339: %w", err)
	}
	var notices []capabilitycontract.Notice
	if strings.TrimSpace(config.NoticesFile) != "" {
		if err := readStrictJSONFile(resolveConfigPath(configDir, config.NoticesFile), &notices); err != nil {
			return err
		}
	}
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract:                 contract,
		PublisherID:              contract.PublisherID,
		ArtifactBaseRef:          config.ArtifactBaseRef,
		GeneratedAt:              generatedAt,
		SourceCommit:             config.SourceCommit,
		MinReDevPluginVersion:    config.MinReDevPluginVersion,
		SignatureKeyID:           privateDoc.KeyID,
		SignaturePolicyEpoch:     config.SignaturePolicyEpoch,
		SignatureRevocationEpoch: config.SignatureRevocationEpoch,
		PrivateKey:               privateKey,
		Notices:                  notices,
	})
	if err != nil {
		return err
	}
	if err := createEmptyDirectory(outputRoot); err != nil {
		return err
	}
	for ref, content := range bundle.Files {
		if err := writeArtifactFile(outputRoot, ref, content); err != nil {
			return err
		}
	}
	if err := writeJSONFile(filepath.Join(outputRoot, hostCapabilityPinFile), bundle.Pin, 0o644); err != nil {
		return err
	}
	return writeJSON(hostCapabilitySummary{
		OK:                true,
		Action:            "build",
		ContractID:        contract.ContractID,
		ContractVersion:   contract.ContractVersion,
		CapabilityID:      contract.CapabilityID,
		CapabilityVersion: contract.CapabilityVersion,
		Pin:               bundle.Pin,
		Output:            filepath.Clean(outputRoot),
	})
}

func generateHostCapabilityClient(artifactRoot, pinFile, publicKeyFile, outputFile string, check bool) error {
	loaded, err := loadVerifiedHostCapability(artifactRoot, pinFile, publicKeyFile)
	if err != nil {
		return err
	}
	client := loaded.Verified.GeneratedClient
	if check {
		current, err := os.ReadFile(outputFile)
		if err != nil {
			return fmt.Errorf("generated host capability client is stale: %w", err)
		}
		if !bytes.Equal(current, client) {
			return errors.New("generated host capability client is stale")
		}
	} else {
		if err := writeBytesFile(outputFile, client, 0o644); err != nil {
			return err
		}
	}
	action := "generate-client"
	if check {
		action = "check-client"
	}
	return writeJSON(hostCapabilitySummary{
		OK:                true,
		Action:            action,
		ContractID:        loaded.Verified.Contract.ContractID,
		ContractVersion:   loaded.Verified.Contract.ContractVersion,
		CapabilityID:      loaded.Verified.Contract.CapabilityID,
		CapabilityVersion: loaded.Verified.Contract.CapabilityVersion,
		Pin:               loaded.Verified.Pin,
		Output:            filepath.Clean(outputFile),
	})
}

func loadVerifiedHostCapability(artifactRoot, pinFile, publicKeyFile string) (loadedHostCapabilityArtifact, error) {
	var pin capabilitycontract.Pin
	if err := readStrictJSONFile(pinFile, &pin); err != nil {
		return loadedHostCapabilityArtifact{}, err
	}
	publicDoc, publicKey, err := readSigningPublicKey(publicKeyFile)
	if err != nil {
		return loadedHostCapabilityArtifact{}, err
	}
	if publicDoc.KeyID != pin.SignatureKeyID {
		return loadedHostCapabilityArtifact{}, errors.New("host capability public key key_id does not match pin")
	}
	if publicDoc.PublisherID != "" && publicDoc.PublisherID != pin.PublisherID {
		return loadedHostCapabilityArtifact{}, errors.New("host capability public key publisher_id does not match pin")
	}
	bundle := capabilitycontract.Bundle{Pin: pin, Files: map[string][]byte{}}
	for _, ref := range hostCapabilityPinRefs(pin) {
		content, err := readArtifactFile(artifactRoot, ref)
		if err != nil {
			return loadedHostCapabilityArtifact{}, err
		}
		bundle.Files[ref] = content
	}
	verified, err := capabilitycontract.Verify(capabilitycontract.VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: pin,
		TrustedKey: capabilitycontract.TrustedKey{
			PublisherID:     pin.PublisherID,
			KeyID:           pin.SignatureKeyID,
			PublicKey:       publicKey,
			PolicyEpoch:     pin.SignaturePolicyEpoch,
			RevocationEpoch: pin.SignatureRevocationEpoch,
		},
		CurrentReDevPluginVersion: version.CurrentCompatibilityVersion(),
	})
	if err != nil {
		return loadedHostCapabilityArtifact{}, err
	}
	return loadedHostCapabilityArtifact{Verified: verified, Bundle: bundle, PublicDoc: publicDoc, PublicKey: publicKey}, nil
}

func hostCapabilityPinRefs(pin capabilitycontract.Pin) []string {
	return []string{
		pin.ArtifactRef,
		pin.ManifestRef,
		pin.SignatureRef,
		pin.CompatibilityRef,
		pin.GeneratedClientRef,
		pin.NoticesRef,
	}
}

func readArtifactFile(root, ref string) ([]byte, error) {
	if err := capabilitycontract.ValidateArtifactRef(ref); err != nil {
		return nil, err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	rootHandle, err := os.OpenRoot(rootAbs)
	if err != nil {
		return nil, err
	}
	defer rootHandle.Close()
	relative := filepath.FromSlash(ref)
	segments := strings.Split(relative, string(filepath.Separator))
	current := ""
	var info os.FileInfo
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, err = rootHandle.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("host capability artifact must be a regular unlinked file")
		}
		if index < len(segments)-1 && !info.IsDir() {
			return nil, errors.New("host capability artifact parent must be a directory")
		}
	}
	if !regularUnlinkedFile(info) {
		return nil, errors.New("host capability artifact must be a regular unlinked file")
	}
	file, err := rootHandle.Open(relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) || !regularUnlinkedFile(openedInfo) {
		return nil, errors.New("host capability artifact changed while opening")
	}
	if openedInfo.Size() < 0 || openedInfo.Size() > capabilitycontract.MaxArtifactFileBytes {
		return nil, errors.New("host capability artifact exceeds the per-file byte budget")
	}
	content, err := io.ReadAll(io.LimitReader(file, capabilitycontract.MaxArtifactFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != openedInfo.Size() || int64(len(content)) > capabilitycontract.MaxArtifactFileBytes {
		return nil, errors.New("host capability artifact changed size while reading")
	}
	return content, nil
}

func regularUnlinkedFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func writeArtifactFile(root, ref string, content []byte) error {
	if err := capabilitycontract.ValidateArtifactRef(ref); err != nil {
		return err
	}
	return writeBytesFile(filepath.Join(root, filepath.FromSlash(ref)), content, 0o644)
}

func readStrictJSONFile(filename string, target any) error {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON document contains multiple values")
		}
		return err
	}
	return nil
}

func resolveConfigPath(base, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(base, value)
}

func createEmptyDirectory(path string) error {
	path = filepath.Clean(path)
	if entries, err := os.ReadDir(path); err == nil {
		if len(entries) != 0 {
			return errors.New("host capability output directory must be empty")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(path, 0o755)
}
