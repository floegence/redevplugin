package authorcandidate

import (
	"errors"
	"testing"
	"time"
)

func candidate(now time.Time) AuthorCandidateRef {
	return AuthorCandidateRef{
		AuthorProjectID: "project-1", OwnerScope: "owner-1",
		SourceSHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PackageSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Generation:    4, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
}

func TestValidateInstallRequestBindsExactCandidate(t *testing.T) {
	now := time.Unix(100, 0)
	c := candidate(now)
	req := AuthorCandidateInstallRequest{OwnerScope: c.OwnerScope, ExpectedSourceSHA256: c.SourceSHA256, ExpectedPackageSHA256: c.PackageSHA256, ExpectedGeneration: c.Generation, Now: now}
	if err := ValidateInstallRequest(c, req); err != nil {
		t.Fatalf("ValidateInstallRequest() error = %v", err)
	}
	for name, mutate := range map[string]func(*AuthorCandidateInstallRequest){
		"owner": func(r *AuthorCandidateInstallRequest) { r.OwnerScope = "other" },
		"source": func(r *AuthorCandidateInstallRequest) {
			r.ExpectedSourceSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"package": func(r *AuthorCandidateInstallRequest) {
			r.ExpectedPackageSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"generation": func(r *AuthorCandidateInstallRequest) { r.ExpectedGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			copy := req
			mutate(&copy)
			if err := ValidateInstallRequest(c, copy); err == nil {
				t.Fatal("expected binding error")
			}
		})
	}
}

func TestValidateInstallRequestRejectsExpiredAndInvalidCandidates(t *testing.T) {
	now := time.Unix(100, 0)
	c := candidate(now)
	c.ExpiresAt = now
	if err := ValidateInstallRequest(c, AuthorCandidateInstallRequest{Now: now}); !errors.Is(err, ErrCandidateExpired) {
		t.Fatalf("expired error = %v", err)
	}
	c = candidate(now)
	c.PackageSHA256 = "bad"
	if err := c.Validate(now); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("invalid error = %v", err)
	}
}
