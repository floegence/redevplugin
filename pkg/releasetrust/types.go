// Package releasetrust defines the host-neutral types and adapter capabilities
// used by the release trust state machine.
package releasetrust

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"slices"
)

var (
	ErrInvalidSourceConfiguration = errors.New("release trust source configuration is invalid")
	ErrSourceChannelNotAllowed    = errors.New("release trust source channel is not allowed")
	ErrInvalidTrustAnchor         = errors.New("release trust anchor is invalid")
	ErrInvalidReleaseTrustOptions = errors.New("release trust options are invalid")

	contractIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

const SignatureAlgorithmEd25519 = "ed25519"

// SourceTrustKey identifies channel-scoped trust state. Values can only be
// derived from a validated SourceConfiguration.
type SourceTrustKey struct {
	sourceID string
	channel  string
}

func (key SourceTrustKey) SourceID() string { return key.sourceID }
func (key SourceTrustKey) Channel() string  { return key.channel }

func (key SourceTrustKey) String() string {
	if !key.valid() {
		return ""
	}
	return key.sourceID + "/" + key.channel
}

func (key SourceTrustKey) valid() bool {
	return contractIDPattern.MatchString(key.sourceID) && contractIDPattern.MatchString(key.channel)
}

// SourceConfiguration is a sealed, immutable source identity and channel set.
type SourceConfiguration struct {
	sourceID        string
	allowedChannels []string
}

func NewSourceConfiguration(sourceID string, allowedChannels []string) (SourceConfiguration, error) {
	if !contractIDPattern.MatchString(sourceID) || len(allowedChannels) == 0 || len(allowedChannels) > 16 {
		return SourceConfiguration{}, ErrInvalidSourceConfiguration
	}
	channels := slices.Clone(allowedChannels)
	slices.Sort(channels)
	for index, channel := range channels {
		if !contractIDPattern.MatchString(channel) || (index > 0 && channels[index-1] == channel) {
			return SourceConfiguration{}, ErrInvalidSourceConfiguration
		}
	}
	return SourceConfiguration{sourceID: sourceID, allowedChannels: channels}, nil
}

func (configuration SourceConfiguration) SourceID() string { return configuration.sourceID }

func (configuration SourceConfiguration) AllowedChannels() []string {
	return slices.Clone(configuration.allowedChannels)
}

func (configuration SourceConfiguration) TrustKey(channel string) (SourceTrustKey, error) {
	if !configuration.valid() {
		return SourceTrustKey{}, ErrInvalidSourceConfiguration
	}
	index, found := slices.BinarySearch(configuration.allowedChannels, channel)
	if !found || index >= len(configuration.allowedChannels) {
		return SourceTrustKey{}, fmt.Errorf("%w: source=%q channel=%q", ErrSourceChannelNotAllowed, configuration.sourceID, channel)
	}
	return SourceTrustKey{sourceID: configuration.sourceID, channel: channel}, nil
}

func (configuration SourceConfiguration) valid() bool {
	if !contractIDPattern.MatchString(configuration.sourceID) || len(configuration.allowedChannels) == 0 || len(configuration.allowedChannels) > 16 || !slices.IsSorted(configuration.allowedChannels) {
		return false
	}
	for index, channel := range configuration.allowedChannels {
		if !contractIDPattern.MatchString(channel) || (index > 0 && configuration.allowedChannels[index-1] == channel) {
			return false
		}
	}
	return true
}

// TrustAnchor is an owned public verification key.
type TrustAnchor struct {
	algorithm string
	keyID     string
	publicKey []byte
}

func NewEd25519TrustAnchor(keyID string, publicKey []byte) (TrustAnchor, error) {
	if !contractIDPattern.MatchString(keyID) || len(publicKey) != ed25519.PublicKeySize || allZero(publicKey) {
		return TrustAnchor{}, ErrInvalidTrustAnchor
	}
	return TrustAnchor{
		algorithm: SignatureAlgorithmEd25519,
		keyID:     keyID,
		publicKey: slices.Clone(publicKey),
	}, nil
}

func (anchor TrustAnchor) Algorithm() string { return anchor.algorithm }
func (anchor TrustAnchor) KeyID() string     { return anchor.keyID }
func (anchor TrustAnchor) PublicKey() []byte { return slices.Clone(anchor.publicKey) }

func (anchor TrustAnchor) valid() bool {
	return anchor.algorithm == SignatureAlgorithmEd25519 && contractIDPattern.MatchString(anchor.keyID) && len(anchor.publicKey) == ed25519.PublicKeySize
}

func cloneTrustAnchor(anchor TrustAnchor) TrustAnchor {
	anchor.publicKey = slices.Clone(anchor.publicKey)
	return anchor
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

// TransparencyRoot identifies one trusted transparency log verification key.
type TransparencyRoot struct {
	logID  string
	anchor TrustAnchor
}

func NewTransparencyRoot(logID string, anchor TrustAnchor) (TransparencyRoot, error) {
	if !contractIDPattern.MatchString(logID) || !anchor.valid() {
		return TransparencyRoot{}, ErrInvalidTrustAnchor
	}
	return TransparencyRoot{logID: logID, anchor: cloneTrustAnchor(anchor)}, nil
}

func (root TransparencyRoot) LogID() string       { return root.logID }
func (root TransparencyRoot) Anchor() TrustAnchor { return cloneTrustAnchor(root.anchor) }

func (root TransparencyRoot) valid() bool {
	return contractIDPattern.MatchString(root.logID) && root.anchor.valid()
}

type SigningLedgerRootMode string

const (
	SigningLedgerRootPinned        SigningLedgerRootMode = "pinned"
	SigningLedgerRootRootDelegated SigningLedgerRootMode = "root_delegated"
)

// SigningLedgerRoot is a closed choice between an independently pinned log
// root and a key selected from a verified release-root delegation.
type SigningLedgerRoot struct {
	mode           SigningLedgerRootMode
	logID          string
	pinnedAnchor   TrustAnchor
	delegatedKeyID string
}

func NewPinnedSigningLedgerRoot(logID string, anchor TrustAnchor) (SigningLedgerRoot, error) {
	if !contractIDPattern.MatchString(logID) || !anchor.valid() {
		return SigningLedgerRoot{}, ErrInvalidTrustAnchor
	}
	return SigningLedgerRoot{
		mode:         SigningLedgerRootPinned,
		logID:        logID,
		pinnedAnchor: cloneTrustAnchor(anchor),
	}, nil
}

func NewDelegatedSigningLedgerRoot(logID, delegatedKeyID string) (SigningLedgerRoot, error) {
	if !contractIDPattern.MatchString(logID) || !contractIDPattern.MatchString(delegatedKeyID) {
		return SigningLedgerRoot{}, ErrInvalidTrustAnchor
	}
	return SigningLedgerRoot{
		mode:           SigningLedgerRootRootDelegated,
		logID:          logID,
		delegatedKeyID: delegatedKeyID,
	}, nil
}

func (root SigningLedgerRoot) Mode() SigningLedgerRootMode { return root.mode }
func (root SigningLedgerRoot) LogID() string               { return root.logID }
func (root SigningLedgerRoot) DelegatedKeyID() string      { return root.delegatedKeyID }

func (root SigningLedgerRoot) PinnedAnchor() (TrustAnchor, bool) {
	if root.mode != SigningLedgerRootPinned {
		return TrustAnchor{}, false
	}
	return cloneTrustAnchor(root.pinnedAnchor), true
}

func (root SigningLedgerRoot) valid() bool {
	switch root.mode {
	case SigningLedgerRootPinned:
		return contractIDPattern.MatchString(root.logID) && root.pinnedAnchor.valid() && root.delegatedKeyID == ""
	case SigningLedgerRootRootDelegated:
		return contractIDPattern.MatchString(root.logID) && contractIDPattern.MatchString(root.delegatedKeyID) && !root.pinnedAnchor.valid()
	default:
		return false
	}
}

type LocatorPolicy uint8

const SourceRelativeLocatorPolicyV1 LocatorPolicy = 1

// ReleaseTrustOptions contains only immutable source trust policy. Runtime
// adapters are supplied separately when the service is constructed.
type ReleaseTrustOptions struct {
	sourceConfiguration SourceConfiguration
	rootAnchor          TrustAnchor
	transparencyRoots   []TransparencyRoot
	signingLedgerRoot   SigningLedgerRoot
	locatorPolicy       LocatorPolicy
}

func NewReleaseTrustOptions(
	sourceConfiguration SourceConfiguration,
	rootAnchor TrustAnchor,
	transparencyRoots []TransparencyRoot,
	signingLedgerRoot SigningLedgerRoot,
	locatorPolicy LocatorPolicy,
) (ReleaseTrustOptions, error) {
	if !sourceConfiguration.valid() || !rootAnchor.valid() || len(transparencyRoots) == 0 || len(transparencyRoots) > 16 || !signingLedgerRoot.valid() || locatorPolicy != SourceRelativeLocatorPolicyV1 {
		return ReleaseTrustOptions{}, ErrInvalidReleaseTrustOptions
	}
	roots := make([]TransparencyRoot, len(transparencyRoots))
	seen := make(map[string]struct{}, len(transparencyRoots))
	for index, root := range transparencyRoots {
		if !root.valid() {
			return ReleaseTrustOptions{}, ErrInvalidReleaseTrustOptions
		}
		if _, exists := seen[root.logID]; exists {
			return ReleaseTrustOptions{}, ErrInvalidReleaseTrustOptions
		}
		seen[root.logID] = struct{}{}
		roots[index] = TransparencyRoot{logID: root.logID, anchor: cloneTrustAnchor(root.anchor)}
	}
	slices.SortFunc(roots, func(left, right TransparencyRoot) int {
		if left.logID < right.logID {
			return -1
		}
		if left.logID > right.logID {
			return 1
		}
		return 0
	})
	return ReleaseTrustOptions{
		sourceConfiguration: SourceConfiguration{sourceID: sourceConfiguration.sourceID, allowedChannels: slices.Clone(sourceConfiguration.allowedChannels)},
		rootAnchor:          cloneTrustAnchor(rootAnchor),
		transparencyRoots:   roots,
		signingLedgerRoot:   cloneSigningLedgerRoot(signingLedgerRoot),
		locatorPolicy:       locatorPolicy,
	}, nil
}

func (options ReleaseTrustOptions) SourceConfiguration() SourceConfiguration {
	return SourceConfiguration{sourceID: options.sourceConfiguration.sourceID, allowedChannels: slices.Clone(options.sourceConfiguration.allowedChannels)}
}

func (options ReleaseTrustOptions) RootAnchor() TrustAnchor {
	return cloneTrustAnchor(options.rootAnchor)
}

func (options ReleaseTrustOptions) TransparencyRoots() []TransparencyRoot {
	roots := make([]TransparencyRoot, len(options.transparencyRoots))
	for index, root := range options.transparencyRoots {
		roots[index] = TransparencyRoot{logID: root.logID, anchor: cloneTrustAnchor(root.anchor)}
	}
	return roots
}

func (options ReleaseTrustOptions) SigningLedgerRoot() SigningLedgerRoot {
	return cloneSigningLedgerRoot(options.signingLedgerRoot)
}

func (options ReleaseTrustOptions) LocatorPolicy() LocatorPolicy { return options.locatorPolicy }

func cloneSigningLedgerRoot(root SigningLedgerRoot) SigningLedgerRoot {
	root.pinnedAnchor = cloneTrustAnchor(root.pinnedAnchor)
	return root
}

func (options ReleaseTrustOptions) valid() bool {
	if !options.sourceConfiguration.valid() || !options.rootAnchor.valid() || len(options.transparencyRoots) == 0 || len(options.transparencyRoots) > 16 ||
		!options.signingLedgerRoot.valid() || options.locatorPolicy != SourceRelativeLocatorPolicyV1 {
		return false
	}
	for index, root := range options.transparencyRoots {
		if !root.valid() || (index > 0 && options.transparencyRoots[index-1].logID >= root.logID) {
			return false
		}
	}
	return true
}
