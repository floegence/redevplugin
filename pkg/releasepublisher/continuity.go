package releasepublisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/version"
)

func readPreviousReleaseState(ctx context.Context, output string, config ConfigV1, pkg pluginpkg.Package) (*previousReleaseStateV1, error) {
	if err := VerifyOutput(ctx, output); err != nil {
		return nil, fmt.Errorf("%w: previous release output: %v", ErrInvalidWorkspace, err)
	}
	reference, files, err := readPublishedReleaseFiles(output)
	if err != nil {
		return nil, err
	}
	previousVersion, previousVersionErr := version.ParseSemVer(reference.ReleaseRef.Version)
	nextVersion, nextVersionErr := version.ParseSemVer(pkg.Manifest.Version())
	if reference.ReleaseRef.SourceID != config.SourceID || reference.ReleaseRef.Channel != config.Channel ||
		reference.ReleaseRef.PublisherID != pkg.Manifest.Publisher.PublisherID || reference.ReleaseRef.PluginID != pkg.Manifest.PluginID() ||
		previousVersionErr != nil || nextVersionErr != nil || nextVersion.Compare(previousVersion) <= 0 ||
		reference.Root != config.Root || reference.SigningLedger != config.SigningLedger {
		return nil, ErrWorkspaceConflict
	}

	rootRaw := files[fmt.Sprintf("sources/%s/root/current.json", config.SourceID)]
	root, err := releasecontract.DecodeRootDelegation(rootRaw)
	if err != nil {
		return nil, ErrInvalidWorkspace
	}
	policyPointerRaw := files[fmt.Sprintf("sources/%s/%s/policy/current.json", config.SourceID, config.Channel)]
	policyPointer, err := releasecontract.DecodeSourcePolicyPointer(policyPointerRaw)
	if err != nil {
		return nil, ErrInvalidWorkspace
	}
	policy, err := releasecontract.DecodeSourcePolicy(files[policyPointer.Ref])
	if err != nil {
		return nil, ErrInvalidWorkspace
	}
	revocationPointerRaw := files[fmt.Sprintf("sources/%s/%s/revocation/current.json", config.SourceID, config.Channel)]
	revocationPointer, err := releasecontract.DecodeRevocationPointer(revocationPointerRaw)
	if err != nil {
		return nil, ErrInvalidWorkspace
	}
	revocation, err := releasecontract.DecodeRevocation(files[revocationPointer.Ref])
	if err != nil {
		return nil, ErrInvalidWorkspace
	}
	if root.RootEpoch != "1" || policy.Epoch != "1" || policyPointer.Epoch != "1" ||
		revocation.Epoch != "1" || revocationPointer.Epoch != "1" {
		return nil, ErrWorkspaceConflict
	}

	stable := []struct {
		usage     releasecontract.SigningUsage
		keyID     string
		subject   releasecontract.SigningSubjectV1
		preimage  []byte
		signature string
	}{
		{releasecontract.SigningUsageRootDelegation, root.KeyID, releasecontract.SigningSubjectV1{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRootDelegation, SourceID: root.SourceID, RootEpoch: root.RootEpoch}, mustSigningPreimage(root.SigningPreimage()), root.Signature},
		{releasecontract.SigningUsageSourcePolicyPointer, policyPointer.KeyID, releasecontract.SigningSubjectV1{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageSourcePolicyPointer, SourceID: policyPointer.SourceID, Channel: policyPointer.Channel, Epoch: policyPointer.Epoch}, mustSigningPreimage(policyPointer.SigningPreimage()), policyPointer.Signature},
		{releasecontract.SigningUsageSourcePolicy, policy.KeyID, releasecontract.SigningSubjectV1{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageSourcePolicy, SourceID: policy.SourceID, Channel: policy.Channel, Epoch: policy.Epoch}, mustSigningPreimage(policy.SigningPreimage()), policy.Signature},
		{releasecontract.SigningUsageRevocationPointer, revocationPointer.KeyID, releasecontract.SigningSubjectV1{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRevocationPointer, SourceID: revocationPointer.SourceID, Channel: revocationPointer.Channel, Epoch: revocationPointer.Epoch}, mustSigningPreimage(revocationPointer.SigningPreimage()), revocationPointer.Signature},
		{releasecontract.SigningUsageRevocation, revocation.KeyID, releasecontract.SigningSubjectV1{SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRevocation, SourceID: revocation.SourceID, Channel: revocation.Channel, Epoch: revocation.Epoch}, mustSigningPreimage(revocation.SigningPreimage()), revocation.Signature},
	}
	requestIDs := make(map[releasecontract.SigningUsage]string, len(stable))
	responses := make(map[string]string, len(stable))
	for _, item := range stable {
		if item.preimage == nil || item.signature == "" {
			return nil, ErrInvalidWorkspace
		}
		request, err := NewExternalSignerRequest(item.usage, item.keyID, item.subject, item.preimage)
		if err != nil {
			return nil, ErrInvalidWorkspace
		}
		requestIDs[item.usage] = request.RequestID
		responses[request.RequestID] = item.signature
	}

	checkpointLocator := fmt.Sprintf("sources/%s/signing-ledger/checkpoints/current.json", config.SourceID)
	checkpointRaw := files[checkpointLocator]
	checkpoint, err := releasecontract.DecodeSigningLedgerCheckpoint(checkpointRaw)
	if err != nil {
		return nil, ErrInvalidWorkspace
	}
	ledgerKey, err := decodePublicKey(config.SigningLedger.PublicKeyV1)
	if err != nil || releasecontract.VerifySigningLedgerCheckpoint(checkpoint, releasecontract.Ed25519PublicKeyVerifier{config.SigningLedger.KeyID: ledgerKey}) != nil {
		return nil, ErrInvalidWorkspace
	}
	leaves, err := readPreviousLedgerLeaves(config.SourceID, files, checkpoint)
	if err != nil {
		return nil, err
	}
	state := &previousReleaseStateV1{
		ReleaseRef: reference.ReleaseRef, StableRequestIDs: requestIDs, StableResponses: responses,
		LedgerLeaves: leaves, Checkpoint: checkpoint, CheckpointBytes: slices.Clone(checkpointRaw),
	}
	if err := validatePreviousReleaseState(state); err != nil {
		return nil, err
	}
	return state, nil
}

func readPublishedReleaseFiles(output string) (PublisherReleaseRefV1, map[string][]byte, error) {
	matches, err := filepath.Glob(filepath.Join(output, "*.release-ref.json"))
	if err != nil || len(matches) != 1 {
		return PublisherReleaseRefV1{}, nil, ErrInvalidWorkspace
	}
	var reference PublisherReleaseRefV1
	if err := readClosedJSONFile(matches[0], &reference, 1<<20); err != nil || reference.SchemaVersion != ReleaseRefSchemaVersion || len(reference.Files) == 0 {
		return PublisherReleaseRefV1{}, nil, ErrInvalidWorkspace
	}
	files := make(map[string][]byte, len(reference.Files))
	for _, file := range reference.Files {
		if file.Locator == "" || file.AssetName == "" || file.Size <= 0 || !isSHA256(file.SHA256) || files[file.Locator] != nil || filepath.Base(file.AssetName) != file.AssetName {
			return PublisherReleaseRefV1{}, nil, ErrInvalidWorkspace
		}
		raw, err := os.ReadFile(filepath.Join(output, file.AssetName))
		if err != nil || int64(len(raw)) != file.Size || sha256Hex(raw) != file.SHA256 {
			return PublisherReleaseRefV1{}, nil, ErrInvalidWorkspace
		}
		files[file.Locator] = raw
	}
	return reference, files, nil
}

func readPreviousLedgerLeaves(sourceID string, files map[string][]byte, checkpoint releasecontract.SigningLedgerCheckpointV1) ([]releasecontract.SigningLedgerLogLeafV1, error) {
	logPrefix := fmt.Sprintf("sources/%s/signing-ledger/log/", sourceID)
	receiptPrefix := fmt.Sprintf("sources/%s/signing-ledger/receipts/", sourceID)
	leaves := make([]releasecontract.SigningLedgerLogLeafV1, 0, checkpoint.TreeSize)
	for locator, raw := range files {
		if strings.HasPrefix(locator, logPrefix) {
			leaf, err := releasecontract.DecodeSigningLedgerLogLeaf(raw)
			if err != nil {
				return nil, ErrInvalidWorkspace
			}
			leaves = append(leaves, leaf)
		}
	}
	if len(leaves) == 0 {
		for locator, raw := range files {
			if !strings.HasPrefix(locator, receiptPrefix) {
				continue
			}
			receipt, err := releasecontract.DecodeSigningLedgerReceipt(raw)
			if err != nil {
				return nil, ErrInvalidWorkspace
			}
			leaves = append(leaves, releasecontract.SigningLedgerLogLeafV1{
				SchemaVersion: releasecontract.SigningLedgerLogLeafSchemaVersion,
				SourceID:      receipt.SourceID, Channel: receipt.Channel,
				SubjectIdentitySHA256:   receipt.SubjectIdentitySHA256,
				SigningPreimageSHA256:   receipt.SigningPreimageSHA256,
				SignatureEnvelopeSHA256: receipt.SignatureEnvelopeSHA256,
				Sequence:                receipt.Sequence,
			})
		}
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Sequence < leaves[j].Sequence })
	if uint64(len(leaves)) != checkpoint.TreeSize {
		return nil, ErrInvalidWorkspace
	}
	hashes := make([][]byte, len(leaves))
	for index, leaf := range leaves {
		if leaf.Sequence != uint64(index+1) {
			return nil, ErrInvalidWorkspace
		}
		raw, err := releasecontract.CanonicalSigningLedgerLogLeaf(leaf)
		if err != nil {
			return nil, ErrInvalidWorkspace
		}
		hashes[index] = merkleLeafHash(raw)
	}
	root, err := hex.DecodeString(checkpoint.LogRootHash)
	if err != nil || !bytes.Equal(merkleRoot(hashes), root) {
		return nil, ErrInvalidWorkspace
	}
	return leaves, nil
}

func mustSigningPreimage(raw []byte, err error) []byte {
	if err != nil {
		return nil
	}
	return raw
}

func validatePreviousReleaseState(state *previousReleaseStateV1) error {
	if state == nil {
		return nil
	}
	if state.ReleaseRef.SourceID == "" || state.ReleaseRef.Channel == "" || len(state.StableRequestIDs) != 5 ||
		len(state.StableResponses) != 5 || len(state.LedgerLeaves) == 0 || state.Checkpoint.TreeSize != uint64(len(state.LedgerLeaves)) ||
		len(state.CheckpointBytes) == 0 {
		return ErrInvalidWorkspace
	}
	canonical, err := releasecontract.CanonicalSigningLedgerCheckpoint(state.Checkpoint)
	if err != nil || !bytes.Equal(canonical, state.CheckpointBytes) {
		return ErrInvalidWorkspace
	}
	for usage, requestID := range state.StableRequestIDs {
		if !validSigningUsage(usage) || !isSHA256(requestID) || state.StableResponses[requestID] == "" {
			return ErrInvalidWorkspace
		}
	}
	return nil
}

func clonePreviousReleaseState(state *previousReleaseStateV1) *previousReleaseStateV1 {
	if state == nil {
		return nil
	}
	clone := *state
	clone.StableRequestIDs = make(map[releasecontract.SigningUsage]string, len(state.StableRequestIDs))
	for key, value := range state.StableRequestIDs {
		clone.StableRequestIDs[key] = value
	}
	clone.StableResponses = cloneStringMap(state.StableResponses)
	clone.LedgerLeaves = slices.Clone(state.LedgerLeaves)
	clone.CheckpointBytes = slices.Clone(state.CheckpointBytes)
	return &clone
}

func equalPreviousReleaseState(left, right *previousReleaseStateV1) bool {
	return reflect.DeepEqual(left, right)
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func validateStableRequest(previous *previousReleaseStateV1, usage releasecontract.SigningUsage, request ExternalSignerRequestV1) error {
	if previous == nil {
		return nil
	}
	if previous.StableRequestIDs[usage] != request.RequestID {
		return ErrWorkspaceConflict
	}
	return nil
}

func verifyPreviousLedgerKey(config ConfigV1, previous *previousReleaseStateV1) error {
	if previous == nil {
		return nil
	}
	key, err := decodePublicKey(config.SigningLedger.PublicKeyV1)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return ErrInvalidWorkspace
	}
	return releasecontract.VerifySigningLedgerCheckpoint(previous.Checkpoint, releasecontract.Ed25519PublicKeyVerifier{config.SigningLedger.KeyID: key})
}
