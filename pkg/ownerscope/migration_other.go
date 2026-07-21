//go:build !darwin && !linux

package ownerscope

import (
	"context"
	"os"
)

type migrationJournalV1 struct{}
type cleanupJournalV1 struct{}

func OpenOwnerScopeMigration(*os.File, OwnerScopeMigrationOptions) (*OwnerScopeMigration, error) {
	return nil, ErrOwnerScopeUnsupported
}

func (*OwnerScopeMigration) QuarantineUnownedLegacy(context.Context) (Status, error) {
	return Status{}, ErrOwnerScopeUnsupported
}

func (*OwnerScopeMigration) CommitFreshGeneration(context.Context) (Status, error) {
	return Status{}, ErrOwnerScopeUnsupported
}

func (*OwnerScopeMigration) DeleteQuarantine(context.Context) (Status, error) {
	return Status{}, ErrOwnerScopeUnsupported
}

func (*OwnerScopeMigration) Close() error { return nil }
