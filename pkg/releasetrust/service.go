package releasetrust

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrReleaseTrustVerification = errors.New("release trust verification failed")
	ErrReleaseTrustExpired      = errors.New("release trust document is expired")
	ErrReleaseTrustRevoked      = errors.New("release trust subject is revoked")
)

type ReleaseTrustAdapters struct {
	Documents ReleaseDocumentTransport
}

type ReleaseTrustService struct {
	options  ReleaseTrustOptions
	adapters ReleaseTrustAdapters
	now      func() time.Time
}

func NewReleaseTrustService(options ReleaseTrustOptions, adapters ReleaseTrustAdapters) (*ReleaseTrustService, error) {
	if !options.valid() || isNilInterface(adapters.Documents) {
		return nil, ErrInvalidReleaseTrustOptions
	}
	return &ReleaseTrustService{options: options, adapters: adapters, now: time.Now}, nil
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
