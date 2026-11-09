// Package authoring provides the shared source-build and isolated preview lifecycle.
// Hosts supply an authenticated platform Host; project commands execute only on
// explicit Build calls. It does not start watchers or grant plugin permissions.
package authoring

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

type PreviewState struct {
	Candidate           bool                  `json:"candidate"`
	SourceHash          string                `json:"source_hash"`
	PackageHash         string                `json:"package_hash"`
	Stages              []authorproject.Stage `json:"stages"`
	Persistent          bool                  `json:"persistent"`
	Manual              bool                  `json:"manual"`
	RestartRequired     bool                  `json:"restart_required"`
	Generation          uint64                `json:"generation"`
	Building            bool                  `json:"building"`
	Error               string                `json:"error"`
	Output              string                `json:"output"`
	PluginInstanceID    string                `json:"plugin_instance_id"`
	ArtifactID          string                `json:"artifact_id,omitempty"`
	CandidateArtifactID string                `json:"candidate_artifact_id,omitempty"`
	CSRF                string                `json:"csrf"`
	Mode                string                `json:"mode"`
}
type Preview struct {
	operation sync.Mutex
	mu        sync.Mutex
	state     PreviewState
	record    registry.PluginRecord
	candidate *authorproject.PipelineResult
}

func (s *Preview) Snapshot() PreviewState {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.state
	snapshot.Stages = slices.Clone(snapshot.Stages)
	return snapshot
}
func (s *Preview) Build(ctx context.Context, p *authorproject.Project, h *host.Host) {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.Lock()
	if s.state.RestartRequired {
		s.mu.Unlock()
		return
	}
	s.state.Building = true
	s.state.Error = ""
	s.state.Candidate = false
	s.state.CandidateArtifactID = ""
	s.candidate = nil
	s.mu.Unlock()
	result, err := p.Build(ctx, authorproject.PipelineOptions{Generate: true})
	s.mu.Lock()
	s.state.Building = false
	s.state.Output = commandOutput(result.Commands)
	s.state.Stages = result.Stages
	if err != nil {
		s.state.Error = err.Error()
		s.mu.Unlock()
		return
	}
	if s.state.Mode == "web" && len(result.Package.Manifest.Workers) > 0 {
		s.state.Error = "This project declares Workers. Prepare a verified runtime and restart dev with --runtime and --runtime-sha256."
		s.mu.Unlock()
		return
	}
	s.candidate = &result
	s.state.Candidate = true
	s.state.SourceHash = result.SourceHash
	manual := s.state.Manual && s.record.PluginInstanceID != ""
	s.mu.Unlock()
	if !manual {
		_ = s.applyLocked(ctx, p, h)
	}
}
func (s *Preview) Apply(ctx context.Context, p *authorproject.Project, h *host.Host, expected ...string) error {
	s.operation.Lock()
	defer s.operation.Unlock()
	if len(expected) > 0 {
		s.mu.Lock()
		matches := s.candidate != nil && s.candidate.SourceHash == expected[0]
		s.mu.Unlock()
		if !matches {
			return errors.New("candidate changed during review; review the new build")
		}
	}
	return s.applyLocked(ctx, p, h)
}
func (s *Preview) applyLocked(ctx context.Context, p *authorproject.Project, h *host.Host) error {
	s.mu.Lock()
	candidate := s.candidate
	current := s.record
	blocked := s.state.RestartRequired
	s.mu.Unlock()
	if blocked || candidate == nil {
		return errors.New("no applicable candidate build")
	}
	var err error
	if p != nil {
		digest, failure := p.Snapshot(ctx)
		err = failure
		if err == nil && digest != candidate.SourceHash {
			err = errors.New("candidate source changed; wait for the next build")
		}
	}
	mutationAttempted := false
	var next registry.PluginRecord
	if err == nil && current.PluginInstanceID != "" {
		var records []registry.PluginRecord
		records, err = h.ListPlugins(ctx)
		found := false
		for _, record := range records {
			if record.PluginInstanceID == current.PluginInstanceID {
				current = record
				found = true
				break
			}
		}
		if err == nil && !found {
			err = errors.New("preview plugin was removed; restart the developer preview")
		}
	}
	if err == nil {
		switch {
		case current.PluginInstanceID == "":
			var id string
			id, err = newInstanceID()
			if err == nil {
				mutationAttempted = true
				next, err = host.ImportLocalPackageBytes(ctx, h, id, candidate.Bytes)
			}
		case current.PackageHash == candidate.Package.PackageHash:
			next = current
		default:
			mutationAttempted = true
			retained := false
			for _, prior := range current.VersionHistory {
				if prior.PackageHash == candidate.Package.PackageHash {
					retained = true
					break
				}
			}
			if retained {
				// Exact retained data generations must follow their package, even
				// when several author revisions share one release version.
				next, err = h.DowngradePlugin(ctx, host.DowngradeRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, PackageHash: candidate.Package.PackageHash})
			} else {
				next, err = h.UpdateLocalPackage(ctx, host.UpdateLocalPackageRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, PackageReader: bytes.NewReader(candidate.Bytes), PackageSize: int64(len(candidate.Bytes))})
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.state.Error = err.Error()
		if mutationAttempted && mutation.ForError(err) != mutation.OutcomeNotCommitted {
			s.state.RestartRequired = true
			s.state.Error = "Package mutation requires reconciliation. Restart this development environment. " + err.Error()
		}
		return err
	}
	s.record = next
	s.state.PluginInstanceID = next.PluginInstanceID
	s.state.PackageHash = next.PackageHash
	s.state.Generation++
	s.state.ArtifactID = s.state.CandidateArtifactID
	s.state.CandidateArtifactID = ""
	s.state.Candidate = false
	s.state.CandidateArtifactID = ""
	s.candidate = nil
	s.state.Error = ""
	return nil
}

func (s *Preview) Reset(ctx context.Context, h *host.Host, expected ...uint64) error {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.Lock()
	record, blocked := s.record, s.state.RestartRequired
	if len(expected) > 0 && s.state.Generation != expected[0] {
		s.mu.Unlock()
		return errors.New("preview changed during reset review; review the current generation")
	}
	s.mu.Unlock()
	if blocked || record.PluginInstanceID == "" {
		return errors.New("preview is not ready for reset")
	}
	records, err := h.ListPlugins(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, current := range records {
		if current.PluginInstanceID == record.PluginInstanceID {
			record = current
			found = true
		}
	}
	if !found {
		return errors.New("preview plugin is absent; restart this environment")
	}
	_, err = h.UninstallPlugin(ctx, host.UninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, DeleteData: true})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.state.Error = err.Error()
		s.state.RestartRequired = mutation.ForError(err) != mutation.OutcomeNotCommitted
		return err
	}
	s.record = registry.PluginRecord{}
	s.candidate = nil
	s.state.Candidate = false
	s.state.PluginInstanceID = ""
	s.state.PackageHash = ""
	s.state.ArtifactID = ""
	s.state.CandidateArtifactID = ""
	return nil
}

// NewPreview resumes the isolated Host inventory. The Host must belong only to
// this author environment; it must never be the product installation Host.
func NewPreview(ctx context.Context, h *host.Host, initial PreviewState) (*Preview, error) {
	records, err := h.ListPlugins(ctx)
	if err != nil {
		return nil, err
	}
	if len(records) > 1 {
		return nil, errors.New("development state contains multiple plugin instances")
	}
	s := &Preview{state: initial}
	if len(records) == 1 {
		s.record = records[0]
		s.state.PluginInstanceID = records[0].PluginInstanceID
		s.state.PackageHash = records[0].PackageHash
		s.state.Generation = 1
	}
	return s, nil
}

// ReportError exposes a watcher failure without replacing the active preview.
func (s *Preview) ReportError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Error = err.Error()
}
func newInstanceID() (string, error) { return "plugini_" + rand.Text(), nil }
func commandOutput(commands []authorproject.CommandResult) string {
	var output strings.Builder
	for _, command := range commands {
		output.WriteString(command.Output)
	}
	return output.String()
}

// StageArtifact selects platform-owned bytes without running project commands.
// It retains the current frame until the caller explicitly applies this artifact.
func (s *Preview) StageArtifact(ctx context.Context, store *WorkspaceStore, owner Owner, workspaceID, artifactID string) error {
	s.operation.Lock()
	defer s.operation.Unlock()
	a, raw, err := store.ReadArtifact(ctx, owner, workspaceID, artifactID)
	if err != nil {
		return err
	}
	pkg, err := pluginpkg.Read(ctx, bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.RestartRequired {
		return errors.New("preview requires reconciliation")
	}
	if s.state.Mode == "web" && len(pkg.Manifest.Workers) > 0 {
		return errors.New("verified Worker runtime is required")
	}
	s.candidate = &authorproject.PipelineResult{Package: pkg, Bytes: raw, SourceHash: a.SourceSHA256, Stages: a.Stages}
	s.state.Candidate = true
	s.state.CandidateArtifactID = a.ID
	s.state.SourceHash = a.SourceSHA256
	s.state.Stages = a.Stages
	s.state.Error = ""
	return nil
}

// ApplyArtifact applies an immutable staged artifact. Unlike the CLI source
// watcher, later edits do not invalidate these already inspected package bytes.
func (s *Preview) ApplyArtifact(ctx context.Context, h *host.Host, artifactID string) error {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.Lock()
	matches := artifactID != "" && s.state.CandidateArtifactID == artifactID
	s.mu.Unlock()
	if !matches {
		return errors.New("preview artifact changed during review")
	}
	return s.applyLocked(ctx, nil, h)
}
