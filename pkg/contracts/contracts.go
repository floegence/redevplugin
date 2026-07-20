// Package contracts exposes the staged ReDevPlugin machine-contract set as an
// opt-in dependency. Importing the normal Host packages does not link the raw
// contract bodies into host binaries.
package contracts

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"
)

type ID string

type Contract struct {
	id      ID
	path    string
	version string
	sha256  string
	body    string
}

func newGeneratedContract(id ID, path string, version string, sha256 string, body string) Contract {
	return Contract{id: id, path: path, version: version, sha256: sha256, body: body}
}

func (c Contract) ID() ID          { return c.id }
func (c Contract) Path() string    { return c.path }
func (c Contract) Version() string { return c.version }
func (c Contract) SHA256() string  { return c.sha256 }
func (c Contract) Bytes() []byte   { return []byte(c.body) }

type ArtifactSnapshot struct {
	ID      ID     `json:"id"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type RegistrySnapshot struct {
	SchemaVersion   string             `json:"schema_version"`
	RegistryVersion string             `json:"registry_version"`
	Artifacts       []ArtifactSnapshot `json:"artifacts"`
}

type GoModuleCoordinate struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}

type NPMPackageCoordinate struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type RustCrateCoordinate struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Role    string `json:"role"`
}

type PackageSetSnapshot struct {
	SchemaVersion           string                 `json:"schema_version"`
	PlatformVersion         string                 `json:"platform_version"`
	GoModule                GoModuleCoordinate     `json:"go_module"`
	NPMPackages             []NPMPackageCoordinate `json:"npm_packages"`
	RustCrates              []RustCrateCoordinate  `json:"rust_crates"`
	ContractRegistryVersion string                 `json:"contract_registry_version"`
	ContractSetSHA256       string                 `json:"contract_set_sha256"`
}

var ErrUnknownID = errors.New("contract id is unknown")

type UnknownIDError struct {
	ID ID
}

func (e *UnknownIDError) Error() string {
	return fmt.Sprintf("contract id %q is unknown", e.ID)
}

func (e *UnknownIDError) Unwrap() error { return ErrUnknownID }

func ContractRegistry() RegistrySnapshot {
	artifacts := make([]ArtifactSnapshot, len(generatedArtifacts))
	for index, contract := range generatedArtifacts {
		artifacts[index] = ArtifactSnapshot{
			ID: contract.id, Path: contract.path, Version: contract.version, SHA256: contract.sha256,
		}
	}
	return RegistrySnapshot{
		SchemaVersion:   generatedRegistrySchemaVersion,
		RegistryVersion: generatedRegistryVersion,
		Artifacts:       artifacts,
	}
}

func PackageSet() PackageSetSnapshot {
	snapshot := generatedPackageSet
	snapshot.NPMPackages = append([]NPMPackageCoordinate(nil), generatedPackageSet.NPMPackages...)
	snapshot.RustCrates = append([]RustCrateCoordinate(nil), generatedPackageSet.RustCrates...)
	return snapshot
}

func RegistryContract() Contract { return generatedRegistryContract }

func Artifacts() []Contract {
	return append([]Contract(nil), generatedArtifacts...)
}

func Open(id ID) (fs.File, error) {
	contract, err := lookup(id)
	if err != nil {
		return nil, err
	}
	return &memoryFile{
		reader: strings.NewReader(contract.body),
		info:   memoryFileInfo{name: string(contract.id), size: int64(len(contract.body))},
	}, nil
}

func Read(id ID) ([]byte, error) {
	contract, err := lookup(id)
	if err != nil {
		return nil, err
	}
	return []byte(contract.body), nil
}

func lookup(id ID) (Contract, error) {
	contract, ok := generatedContractByID[id]
	if !ok {
		return Contract{}, &UnknownIDError{ID: id}
	}
	return contract, nil
}

type memoryFile struct {
	reader *strings.Reader
	info   memoryFileInfo
}

func (f *memoryFile) Read(buffer []byte) (int, error) { return f.reader.Read(buffer) }
func (*memoryFile) Close() error                      { return nil }
func (f *memoryFile) Stat() (fs.FileInfo, error)      { return f.info, nil }

type memoryFileInfo struct {
	name string
	size int64
}

func (i memoryFileInfo) Name() string     { return i.name }
func (i memoryFileInfo) Size() int64      { return i.size }
func (memoryFileInfo) Mode() fs.FileMode  { return 0o444 }
func (memoryFileInfo) ModTime() time.Time { return time.Time{} }
func (memoryFileInfo) IsDir() bool        { return false }
func (memoryFileInfo) Sys() any           { return nil }
