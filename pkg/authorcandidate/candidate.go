// Package authorcandidate defines the host-neutral handoff contract between
// an authoring workspace and the plugin lifecycle.
//
// Deprecated: use pkg/authoring immutable artifacts and Host inspected installs.
// This legacy validator is retained for source compatibility only; it does not
// grant execution or replace the platform installation transaction.
package authorcandidate

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidCandidate        = errors.New("author candidate is invalid")
	ErrCandidateExpired        = errors.New("author candidate has expired")
	ErrCandidateSourceChanged  = errors.New("author candidate source changed")
	ErrCandidatePackageChanged = errors.New("author candidate package changed")
	ErrCandidateOwnerMismatch  = errors.New("author candidate owner scope mismatch")
	ErrCandidateGeneration     = errors.New("author candidate generation is stale")
)

// AuthorCandidateRef identifies one immutable package candidate produced by a
// selected author project. The bytes are never inferred from the source path;
// the hashes and generation are the review and install boundary.
type AuthorCandidateRef struct {
	AuthorProjectID string    `json:"author_project_id"`
	OwnerScope      string    `json:"owner_scope"`
	SourceSHA256    string    `json:"source_sha256"`
	PackageSHA256   string    `json:"package_sha256"`
	Generation      uint64    `json:"generation"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// AuthorCandidateInspection is the review projection for a candidate. Hosts
// may add presentation fields around it, but must preserve this exact binding.
type AuthorCandidateInspection struct {
	Candidate AuthorCandidateRef `json:"candidate"`
	PluginID  string             `json:"plugin_id"`
	Version   string             `json:"version"`
	PreviewID string             `json:"preview_id,omitempty"`
}

// AuthorCandidateInstallRequest is the explicit confirmation sent by a host
// after the user reviews the candidate bytes and selects Install.
type AuthorCandidateInstallRequest struct {
	Candidate             AuthorCandidateRef `json:"candidate"`
	OwnerScope            string             `json:"owner_scope"`
	ExpectedSourceSHA256  string             `json:"expected_source_sha256"`
	ExpectedPackageSHA256 string             `json:"expected_package_sha256"`
	ExpectedGeneration    uint64             `json:"expected_generation"`
	Now                   time.Time          `json:"-"`
}

func (r AuthorCandidateRef) validate(now time.Time) error {
	if strings.TrimSpace(r.AuthorProjectID) == "" || strings.TrimSpace(r.OwnerScope) == "" ||
		!validSHA256(r.SourceSHA256) || !validSHA256(r.PackageSHA256) || r.Generation == 0 {
		return fmt.Errorf("%w: missing identity or digest", ErrInvalidCandidate)
	}
	if r.IssuedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) {
		return fmt.Errorf("%w: invalid lifetime", ErrInvalidCandidate)
	}
	if !now.IsZero() && !r.ExpiresAt.After(now) {
		return ErrCandidateExpired
	}
	return nil
}

// Validate checks the candidate's immutable identity and lifetime.
func (r AuthorCandidateRef) Validate(now time.Time) error { return r.validate(now) }

// ValidateInstallRequest verifies that the explicit install confirmation is
// still bound to the reviewed candidate. A host should call this immediately
// before invoking the lifecycle install operation.
func ValidateInstallRequest(candidate AuthorCandidateRef, request AuthorCandidateInstallRequest) error {
	now := request.Now
	if now.IsZero() {
		now = time.Now()
	}
	if err := candidate.validate(now); err != nil {
		return err
	}
	if request.OwnerScope != candidate.OwnerScope {
		return ErrCandidateOwnerMismatch
	}
	if request.ExpectedSourceSHA256 != candidate.SourceSHA256 {
		return ErrCandidateSourceChanged
	}
	if request.ExpectedPackageSHA256 != candidate.PackageSHA256 {
		return ErrCandidatePackageChanged
	}
	if request.ExpectedGeneration != candidate.Generation {
		return ErrCandidateGeneration
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
