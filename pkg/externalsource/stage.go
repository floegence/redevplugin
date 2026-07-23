package externalsource

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

const MaxArtifactBytes int64 = 256 << 20

const (
	defaultMaxConcurrentFetches            = 8
	defaultMaxOwnerConcurrentFetches       = 2
	defaultMaxStagedBytes            int64 = 4 * MaxArtifactBytes
	defaultMaxOwnerStagedBytes       int64 = 2 * MaxArtifactBytes
)

var stageIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// StagedArtifact is a path-free handle to exact bytes owned by StageStore.
type StagedArtifact struct {
	ID     string
	Size   int64
	SHA256 string
}

// StageStoreOptions bounds concurrent external transfers and retained stage bytes.
// Quota keys are opaque host-derived owner identifiers and are never persisted.
type StageStoreOptions struct {
	MaxConcurrentFetches      int
	MaxOwnerConcurrentFetches int
	MaxStagedBytes            int64
	MaxOwnerStagedBytes       int64
}

type stageQuotaState struct {
	activeFetches      int
	ownerActiveFetches map[string]int
	stagedBytes        int64
	ownerStagedBytes   map[string]int64
	reservedBytes      int64
	ownerReservedBytes map[string]int64
	artifacts          map[string]stageArtifactQuota
}

type stageArtifactQuota struct {
	ownerKey string
	size     int64
}

// StageStore owns external artifacts in a host-selected private directory.
type StageStore struct {
	root    *os.Root
	options StageStoreOptions
	mu      sync.Mutex
	quota   stageQuotaState
}

func NewStageStore(directory string) (*StageStore, error) {
	return NewStageStoreWithOptions(directory, StageStoreOptions{})
}

func NewStageStoreWithOptions(directory string, options StageStoreOptions) (*StageStore, error) {
	if directory == "" || strings.TrimSpace(directory) != directory {
		return nil, externalError(ErrorStageInvalid, "open_stage", "", fmt.Errorf("stage directory is required"))
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, externalError(ErrorStageInvalid, "open_stage", "", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, externalError(ErrorStageInvalid, "open_stage", "", fmt.Errorf("stage root must be a directory"))
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, externalError(ErrorStageInvalid, "open_stage", "", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, externalError(ErrorStageInvalid, "open_stage", "", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, externalError(ErrorStageInvalid, "open_stage", "", fmt.Errorf("stage root changed during open"))
	}
	if err := removeOrphanStages(root); err != nil {
		_ = root.Close()
		return nil, externalError(ErrorStageInvalid, "open_stage", "", err)
	}
	options, err = normalizeStageStoreOptions(options)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &StageStore{
		root: root, options: options,
		quota: stageQuotaState{
			ownerActiveFetches: make(map[string]int), ownerStagedBytes: make(map[string]int64),
			ownerReservedBytes: make(map[string]int64), artifacts: make(map[string]stageArtifactQuota),
		},
	}, nil
}

func normalizeStageStoreOptions(options StageStoreOptions) (StageStoreOptions, error) {
	if options.MaxConcurrentFetches == 0 {
		options.MaxConcurrentFetches = defaultMaxConcurrentFetches
	}
	if options.MaxOwnerConcurrentFetches == 0 {
		options.MaxOwnerConcurrentFetches = min(defaultMaxOwnerConcurrentFetches, options.MaxConcurrentFetches)
	}
	if options.MaxStagedBytes == 0 {
		options.MaxStagedBytes = defaultMaxStagedBytes
	}
	if options.MaxOwnerStagedBytes == 0 {
		options.MaxOwnerStagedBytes = min(defaultMaxOwnerStagedBytes, options.MaxStagedBytes)
	}
	if options.MaxConcurrentFetches < 1 || options.MaxOwnerConcurrentFetches < 1 ||
		options.MaxOwnerConcurrentFetches > options.MaxConcurrentFetches ||
		options.MaxStagedBytes < 1 || options.MaxOwnerStagedBytes < 1 || options.MaxOwnerStagedBytes > options.MaxStagedBytes {
		return StageStoreOptions{}, externalError(ErrorStageInvalid, "open_stage", "", fmt.Errorf("stage quota options are invalid"))
	}
	return options, nil
}

// removeOrphanStages runs before a StageStore becomes usable. Because the
// selected root is private to one store lifecycle, every well-formed stage
// file present at startup belongs to an interrupted prior lifecycle.
func removeOrphanStages(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		name := entry.Name()
		id, ok := strings.CutSuffix(name, ".artifact")
		if !ok || !stageIDPattern.MatchString(id) {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || stageLinkCount(info) != 1 {
			continue
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (store *StageStore) Close() error {
	if store == nil || store.root == nil {
		return nil
	}
	return store.root.Close()
}

// Stage streams at most MaxArtifactBytes into an exclusive 0600 regular file.
func (store *StageStore) Stage(ctx context.Context, source io.Reader) (StagedArtifact, error) {
	return store.stageWithLimitForOwner(ctx, "", source, MaxArtifactBytes)
}

// StageUpload streams an owner-scoped upload into the shared external artifact
// stage. A negative declaredSize means the size is unknown. Zero is an
// explicitly empty upload and is rejected before source is read.
func (store *StageStore) StageUpload(ctx context.Context, ownerKey string, source io.Reader, declaredSize int64) (StagedArtifact, error) {
	return store.stageUploadWithLimit(ctx, ownerKey, source, declaredSize, MaxArtifactBytes)
}

func (store *StageStore) stageUploadWithLimit(ctx context.Context, ownerKey string, source io.Reader, declaredSize, limit int64) (StagedArtifact, error) {
	if store == nil || store.root == nil || source == nil {
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage_upload", "", fmt.Errorf("upload stage request is invalid"))
	}
	if limit <= 0 || limit > MaxArtifactBytes {
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage_upload", "", fmt.Errorf("upload stage limit is invalid"))
	}
	if declaredSize == 0 {
		return StagedArtifact{}, externalError(ErrorArtifactEmpty, "stage_upload", "", fmt.Errorf("declared upload is empty"))
	}
	if declaredSize > limit {
		return StagedArtifact{}, externalError(ErrorArtifactTooLarge, "stage_upload", "", fmt.Errorf("declared upload exceeds byte limit"))
	}
	releaseTransfer, err := store.acquireTransfer(ownerKey, "upload_quota")
	if err != nil {
		return StagedArtifact{}, err
	}
	defer releaseTransfer()

	initialReservation := declaredSize
	if initialReservation < 0 {
		initialReservation = 0
	}
	return store.stageWithReservationForOwner(ctx, ownerKey, source, limit, initialReservation)
}

func (store *StageStore) stageWithLimit(ctx context.Context, source io.Reader, limit int64) (StagedArtifact, error) {
	return store.stageWithLimitForOwner(ctx, "", source, limit)
}

func (store *StageStore) stageWithLimitForOwner(ctx context.Context, ownerKey string, source io.Reader, limit int64) (StagedArtifact, error) {
	return store.stageWithReservationForOwner(ctx, ownerKey, source, limit, limit)
}

func (store *StageStore) stageWithReservationForOwner(ctx context.Context, ownerKey string, source io.Reader, limit, initialReservation int64) (StagedArtifact, error) {
	if store == nil || store.root == nil || source == nil || limit <= 0 || limit > MaxArtifactBytes {
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage", "", fmt.Errorf("stage request is invalid"))
	}
	if initialReservation < 0 || initialReservation > limit {
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage", "", fmt.Errorf("stage reservation is invalid"))
	}
	ownerKey = normalizeStageOwnerKey(ownerKey)
	if err := store.reserveStageBytes(ownerKey, initialReservation); err != nil {
		return StagedArtifact{}, err
	}
	reserved := initialReservation
	reservationActive := true
	defer func() {
		if reservationActive {
			store.releaseStageReservation(ownerKey, reserved)
		}
	}()
	id, err := randomStageID()
	if err != nil {
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage", "", err)
	}
	name := stageFilename(id)
	file, err := store.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage", "", err)
	}
	cleanup := func() {
		_ = file.Close()
		_ = store.root.Remove(name)
	}

	hash := sha256.New()
	quotaWriter := &stageQuotaWriter{
		store: store, ownerKey: ownerKey, destination: io.MultiWriter(file, hash),
		limit: limit, reserved: &reserved,
	}
	written, err := copyContext(ctx, quotaWriter, io.LimitReader(source, limit+1))
	if err != nil {
		cleanup()
		if CodeOf(err) != "" {
			return StagedArtifact{}, err
		}
		return StagedArtifact{}, externalError(ErrorTransport, "stage", "", err)
	}
	if written > limit {
		cleanup()
		return StagedArtifact{}, externalError(ErrorArtifactTooLarge, "stage", "", fmt.Errorf("artifact exceeded byte limit"))
	}
	if written == 0 {
		cleanup()
		return StagedArtifact{}, externalError(ErrorArtifactEmpty, "stage", "", fmt.Errorf("artifact is empty"))
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage", "", err)
	}
	info, err := file.Stat()
	if err != nil || !validStageFileInfo(info, written) {
		cleanup()
		return StagedArtifact{}, externalError(ErrorStageIntegrity, "stage", "", fmt.Errorf("staged file metadata is invalid"))
	}
	if err := file.Close(); err != nil {
		_ = store.root.Remove(name)
		return StagedArtifact{}, externalError(ErrorStageInvalid, "stage", "", err)
	}
	store.commitStageReservation(ownerKey, id, reserved, written)
	reservationActive = false
	return StagedArtifact{ID: id, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

// stageQuotaWriter reserves retained-stage capacity before writing each byte
// within limit. The single limit-probe byte is never retained: it exists only
// long enough to classify an oversized stream and is removed on that error.
type stageQuotaWriter struct {
	store       *StageStore
	ownerKey    string
	destination io.Writer
	limit       int64
	written     int64
	reserved    *int64
}

func (writer *stageQuotaWriter) Write(value []byte) (int, error) {
	retainedAfterWrite := min(writer.written+int64(len(value)), writer.limit)
	if additional := retainedAfterWrite - *writer.reserved; additional > 0 {
		if err := writer.store.reserveStageBytes(writer.ownerKey, additional); err != nil {
			return 0, err
		}
		*writer.reserved += additional
	}
	written, err := writer.destination.Write(value)
	writer.written += int64(written)
	return written, err
}

// VerifyPackage safely reopens, rehashes, reparses, and rehashes the same file
// descriptor before returning a package. The second hash detects mutation that
// overlaps package parsing.
func (store *StageStore) VerifyPackage(ctx context.Context, artifact StagedArtifact, limits pluginpkg.ReadLimits) (pluginpkg.Package, error) {
	file, err := store.openVerified(ctx, artifact)
	if err != nil {
		return pluginpkg.Package{}, err
	}
	defer file.Close()

	pkg, parseErr := pluginpkg.Read(ctx, file, artifact.Size, limits)
	if parseErr != nil {
		return pluginpkg.Package{}, parseErr
	}
	if err := verifyOpenStage(ctx, file, artifact); err != nil {
		return pluginpkg.Package{}, err
	}
	return pkg, nil
}

func (store *StageStore) openVerified(ctx context.Context, artifact StagedArtifact) (*os.File, error) {
	if store == nil || store.root == nil || !validStagedArtifact(artifact) {
		return nil, externalError(ErrorStageInvalid, "verify_stage", "", fmt.Errorf("staged artifact handle is invalid"))
	}
	name := stageFilename(artifact.ID)
	before, err := store.root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !validStageFileInfo(before, artifact.Size) {
		return nil, externalError(ErrorStageIntegrity, "verify_stage", "", fmt.Errorf("staged artifact metadata changed"))
	}
	file, err := store.root.Open(name)
	if err != nil {
		return nil, externalError(ErrorStageIntegrity, "verify_stage", "", err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !validStageFileInfo(after, artifact.Size) {
		_ = file.Close()
		return nil, externalError(ErrorStageIntegrity, "verify_stage", "", fmt.Errorf("staged artifact changed during reopen"))
	}
	if err := verifyOpenStage(ctx, file, artifact); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func verifyOpenStage(ctx context.Context, file *os.File, artifact StagedArtifact) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return externalError(ErrorStageIntegrity, "verify_stage", "", err)
	}
	hash := sha256.New()
	read, err := copyContext(ctx, hash, io.LimitReader(file, artifact.Size+1))
	if err != nil {
		return externalError(ErrorStageIntegrity, "verify_stage", "", err)
	}
	if read != artifact.Size || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(artifact.SHA256)) != 1 {
		return externalError(ErrorStageIntegrity, "verify_stage", "", fmt.Errorf("staged artifact hash changed"))
	}
	info, err := file.Stat()
	if err != nil || !validStageFileInfo(info, artifact.Size) {
		return externalError(ErrorStageIntegrity, "verify_stage", "", fmt.Errorf("staged artifact metadata changed"))
	}
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return externalError(ErrorStageIntegrity, "verify_stage", "", err)
	}
	return nil
}

func (store *StageStore) Remove(artifact StagedArtifact) error {
	if store == nil || store.root == nil || !stageIDPattern.MatchString(artifact.ID) {
		return externalError(ErrorStageInvalid, "remove_stage", "", fmt.Errorf("staged artifact handle is invalid"))
	}
	if err := store.root.Remove(stageFilename(artifact.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return externalError(ErrorStageInvalid, "remove_stage", "", err)
	}
	store.releaseStagedArtifact(artifact.ID)
	return nil
}

func normalizeStageOwnerKey(ownerKey string) string {
	ownerKey = strings.TrimSpace(ownerKey)
	if ownerKey == "" {
		return "_default"
	}
	return ownerKey
}

func (store *StageStore) acquireFetch(ownerKey string) (func(), error) {
	return store.acquireTransfer(ownerKey, "fetch_quota")
}

func (store *StageStore) acquireTransfer(ownerKey, operation string) (func(), error) {
	if store == nil || store.root == nil {
		return nil, externalError(ErrorStageInvalid, operation, "", fmt.Errorf("stage store is not initialized"))
	}
	ownerKey = normalizeStageOwnerKey(ownerKey)
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.quota.activeFetches >= store.options.MaxConcurrentFetches ||
		store.quota.ownerActiveFetches[ownerKey] >= store.options.MaxOwnerConcurrentFetches {
		return nil, externalError(ErrorQuotaExceeded, operation, "", fmt.Errorf("concurrent transfer quota exceeded"))
	}
	store.quota.activeFetches++
	store.quota.ownerActiveFetches[ownerKey]++
	var once sync.Once
	return func() {
		once.Do(func() {
			store.mu.Lock()
			store.quota.activeFetches--
			store.quota.ownerActiveFetches[ownerKey]--
			if store.quota.ownerActiveFetches[ownerKey] == 0 {
				delete(store.quota.ownerActiveFetches, ownerKey)
			}
			store.mu.Unlock()
		})
	}, nil
}

func (store *StageStore) reserveStageBytes(ownerKey string, bytes int64) error {
	if bytes == 0 {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.quota.stagedBytes+store.quota.reservedBytes+bytes > store.options.MaxStagedBytes ||
		store.quota.ownerStagedBytes[ownerKey]+store.quota.ownerReservedBytes[ownerKey]+bytes > store.options.MaxOwnerStagedBytes {
		return externalError(ErrorQuotaExceeded, "stage_quota", "", fmt.Errorf("staged byte quota exceeded"))
	}
	store.quota.reservedBytes += bytes
	store.quota.ownerReservedBytes[ownerKey] += bytes
	return nil
}

func (store *StageStore) releaseStageReservation(ownerKey string, bytes int64) {
	if bytes == 0 {
		return
	}
	store.mu.Lock()
	store.quota.reservedBytes -= bytes
	store.quota.ownerReservedBytes[ownerKey] -= bytes
	if store.quota.ownerReservedBytes[ownerKey] == 0 {
		delete(store.quota.ownerReservedBytes, ownerKey)
	}
	store.mu.Unlock()
}

func (store *StageStore) commitStageReservation(ownerKey, artifactID string, reserved, actual int64) {
	store.mu.Lock()
	store.quota.reservedBytes -= reserved
	store.quota.ownerReservedBytes[ownerKey] -= reserved
	if store.quota.ownerReservedBytes[ownerKey] == 0 {
		delete(store.quota.ownerReservedBytes, ownerKey)
	}
	store.quota.stagedBytes += actual
	store.quota.ownerStagedBytes[ownerKey] += actual
	store.quota.artifacts[artifactID] = stageArtifactQuota{ownerKey: ownerKey, size: actual}
	store.mu.Unlock()
}

func (store *StageStore) releaseStagedArtifact(artifactID string) {
	store.mu.Lock()
	artifact, ok := store.quota.artifacts[artifactID]
	if ok {
		delete(store.quota.artifacts, artifactID)
		store.quota.stagedBytes -= artifact.size
		store.quota.ownerStagedBytes[artifact.ownerKey] -= artifact.size
		if store.quota.ownerStagedBytes[artifact.ownerKey] == 0 {
			delete(store.quota.ownerStagedBytes, artifact.ownerKey)
		}
	}
	store.mu.Unlock()
}

func randomStageID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func stageFilename(id string) string { return id + ".artifact" }

func validStagedArtifact(artifact StagedArtifact) bool {
	if !stageIDPattern.MatchString(artifact.ID) || artifact.Size <= 0 || artifact.Size > MaxArtifactBytes || len(artifact.SHA256) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(artifact.SHA256)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(artifact.SHA256) == artifact.SHA256
}

func validStageFileInfo(info os.FileInfo, expectedSize int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && info.Size() == expectedSize && stageLinkCount(info) == 1
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}
