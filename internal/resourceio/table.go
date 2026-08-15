package resourceio

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type HandleID uint64

var (
	ErrInvalidHandle  = errors.New("resource handle is invalid")
	ErrResourceClosed = errors.New("resource is closed")
	ErrOwnerMismatch  = errors.New("resource handle owner mismatch")
	ErrResourceLimit  = errors.New("resource limit exceeded")
)

const (
	IOFlagEOF         uint32 = 1 << 0
	IOFlagText        uint32 = 1 << 1
	IOFlagBinary      uint32 = 1 << 2
	IOFlagMessageEnd  uint32 = 1 << 3
	IOFlagDatagramEnd uint32 = 1 << 4
)

const knownIOFlags = IOFlagEOF | IOFlagText | IOFlagBinary | IOFlagMessageEnd | IOFlagDatagramEnd

type ChunkReader interface {
	ReadChunk(context.Context, []byte) (int, uint32, error)
}

type ChunkWriter interface {
	WriteChunk(context.Context, []byte, uint32) (int, error)
}

type OwnedChunkWriter interface {
	WriteOwnedChunk(context.Context, Owner, []byte, uint32) (int, error)
}

type FullDuplexResource interface {
	FullDuplexResource()
}

type Kind string

const (
	KindFile        Kind = "file"
	KindDirectory   Kind = "directory"
	KindWatch       Kind = "watch"
	KindHTTPUpload  Kind = "http_upload"
	KindHTTPBody    Kind = "http_body"
	KindWebSocket   Kind = "websocket"
	KindTCP         Kind = "tcp"
	KindTCPListener Kind = "tcp_listener"
	KindUDP         Kind = "udp"
)

type Lifetime string

const (
	LifetimeInvocation Lifetime = "invocation"
	LifetimeSession    Lifetime = "session"
)

const (
	MinimumFileHandles      = 64
	MinimumConnections      = 32
	MinimumWatchesListeners = 8
)

type Limits struct {
	FileHandles      int
	Connections      int
	WatchesListeners int
}

func DefaultLimits() Limits {
	return Limits{
		FileHandles:      MinimumFileHandles,
		Connections:      MinimumConnections,
		WatchesListeners: MinimumWatchesListeners,
	}
}

func (limits Limits) valid() bool {
	return limits.FileHandles >= MinimumFileHandles &&
		limits.Connections >= MinimumConnections &&
		limits.WatchesListeners >= MinimumWatchesListeners
}

type Owner struct {
	PluginInstanceID   string
	ActiveFingerprint  string
	Scope              sessionctx.ResourceScope
	Session            sessionctx.SessionScope
	RuntimeGeneration  string
	ManagementRevision uint64
	RevokeEpoch        uint64
	InvocationID       string
	Lifetime           Lifetime
}

func (owner Owner) matches(candidate Owner) bool {
	if owner.PluginInstanceID != candidate.PluginInstanceID || owner.ActiveFingerprint != candidate.ActiveFingerprint || owner.RuntimeGeneration != candidate.RuntimeGeneration || owner.ManagementRevision != candidate.ManagementRevision || owner.RevokeEpoch != candidate.RevokeEpoch || !owner.Scope.Matches(candidate.Scope) || !owner.Session.Matches(candidate.Session) {
		return false
	}
	if owner.Lifetime == LifetimeInvocation && owner.InvocationID != candidate.InvocationID {
		return false
	}
	return true
}

func (owner Owner) valid() bool {
	return owner.PluginInstanceID != "" && owner.ActiveFingerprint != "" &&
		owner.Scope.Valid() && owner.Session.Valid() && owner.RuntimeGeneration != "" &&
		(owner.Lifetime == LifetimeSession || owner.Lifetime == LifetimeInvocation) &&
		(owner.Lifetime != LifetimeInvocation || owner.InvocationID != "")
}

func (owner Owner) samePrincipal(candidate Owner) bool {
	return owner.PluginInstanceID == candidate.PluginInstanceID &&
		owner.Scope.Matches(candidate.Scope) && owner.Session.Matches(candidate.Session) &&
		owner.Lifetime == candidate.Lifetime &&
		(owner.Lifetime != LifetimeInvocation || owner.InvocationID == candidate.InvocationID)
}

type Entry struct {
	ID       HandleID
	Owner    Owner
	Kind     Kind
	Resource io.Closer

	operationMu sync.Mutex
	readMu      sync.Mutex
	writeMu     sync.Mutex
	controlMu   sync.Mutex
	stateMu     sync.Mutex
	closed      bool
}

type Table struct {
	mu      sync.Mutex
	entries map[HandleID]*Entry
	limits  Limits
}

func NewTable(max int) (*Table, error) {
	if max <= 0 {
		return nil, ErrResourceLimit
	}
	return &Table{entries: make(map[HandleID]*Entry), limits: Limits{FileHandles: max, Connections: max, WatchesListeners: max}}, nil
}

func NewTableWithLimits(limits Limits) (*Table, error) {
	if !limits.valid() {
		return nil, ErrResourceLimit
	}
	return &Table{entries: make(map[HandleID]*Entry), limits: limits}, nil
}

func randomHandle() (HandleID, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	id := HandleID(binary.BigEndian.Uint64(raw[:]))
	if id == 0 {
		return randomHandle()
	}
	return id, nil
}

func (table *Table) Open(owner Owner, kind Kind, resource io.Closer) (HandleID, error) {
	if table == nil || resource == nil || !owner.valid() || !validKind(kind) {
		return 0, ErrInvalidHandle
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.ownerKindCountLocked(owner, kindClassFor(kind)) >= table.limitFor(kind) {
		return 0, ErrResourceLimit
	}
	for {
		id, err := randomHandle()
		if err != nil {
			return 0, err
		}
		if _, exists := table.entries[id]; exists {
			continue
		}
		table.entries[id] = &Entry{ID: id, Owner: owner, Kind: kind, Resource: resource}
		return id, nil
	}
}

type kindClass uint8

const (
	kindClassFile kindClass = iota + 1
	kindClassConnection
	kindClassWatchListener
)

func validKind(kind Kind) bool {
	switch kind {
	case KindFile, KindDirectory, KindWatch, KindHTTPUpload, KindHTTPBody, KindWebSocket, KindTCP, KindTCPListener, KindUDP:
		return true
	default:
		return false
	}
}

func kindClassFor(kind Kind) kindClass {
	switch kind {
	case KindWatch, KindTCPListener:
		return kindClassWatchListener
	case KindHTTPUpload, KindHTTPBody, KindWebSocket, KindTCP, KindUDP:
		return kindClassConnection
	default:
		return kindClassFile
	}
}

func (table *Table) limitFor(kind Kind) int {
	switch kindClassFor(kind) {
	case kindClassConnection:
		return table.limits.Connections
	case kindClassWatchListener:
		return table.limits.WatchesListeners
	default:
		return table.limits.FileHandles
	}
}

func (table *Table) ownerKindCountLocked(owner Owner, class kindClass) int {
	count := 0
	for _, entry := range table.entries {
		if entry.Owner.PluginInstanceID == owner.PluginInstanceID &&
			entry.Owner.Scope.Matches(owner.Scope) && kindClassFor(entry.Kind) == class {
			count++
		}
	}
	return count
}

func (table *Table) getLocked(id HandleID, owner Owner) (*Entry, error) {
	entry, ok := table.entries[id]
	if !ok {
		return nil, ErrResourceClosed
	}
	if !entry.Owner.matches(owner) {
		return nil, ErrOwnerMismatch
	}
	return entry, nil
}

func (table *Table) Close(id HandleID, owner Owner) error {
	if table == nil {
		return nil
	}
	table.mu.Lock()
	entry, ok := table.entries[id]
	if !ok {
		table.mu.Unlock()
		return nil
	}
	if !entry.Owner.matches(owner) {
		table.mu.Unlock()
		return ErrOwnerMismatch
	}
	delete(table.entries, id)
	table.mu.Unlock()
	return entry.close()
}

func (table *Table) Read(ctx context.Context, id HandleID, owner Owner, destination []byte) (int, error) {
	n, _, err := table.ReadChunk(ctx, id, owner, destination)
	return n, err
}

func (table *Table) ReadChunk(ctx context.Context, id HandleID, owner Owner, destination []byte) (int, uint32, error) {
	if len(destination) == 0 || len(destination) > 64<<10 {
		return 0, 0, ErrResourceLimit
	}
	entry, release, err := table.acquire(id, owner, false)
	if err != nil {
		return 0, 0, err
	}
	defer release()
	if reader, ok := entry.Resource.(ChunkReader); ok {
		n, flags, err := reader.ReadChunk(ctx, destination)
		if entry.isClosed() {
			return 0, 0, ErrResourceClosed
		}
		if n < 0 || n > len(destination) || flags&^knownIOFlags != 0 {
			return 0, 0, ErrInvalidHandle
		}
		return n, flags, err
	}
	reader, ok := entry.Resource.(io.Reader)
	if !ok {
		return 0, 0, ErrInvalidHandle
	}
	select {
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	default:
	}
	n, err := reader.Read(destination)
	if entry.isClosed() {
		return 0, 0, ErrResourceClosed
	}
	if errors.Is(err, io.EOF) {
		return n, IOFlagEOF, nil
	}
	return n, 0, err
}

func (table *Table) Write(ctx context.Context, id HandleID, owner Owner, source []byte) (int, error) {
	return table.WriteChunk(ctx, id, owner, source, 0)
}

func (table *Table) WriteChunk(ctx context.Context, id HandleID, owner Owner, source []byte, flags uint32) (int, error) {
	if len(source) > 64<<10 {
		return 0, ErrResourceLimit
	}
	if flags&^knownIOFlags != 0 {
		return 0, ErrInvalidHandle
	}
	entry, release, err := table.acquire(id, owner, true)
	if err != nil {
		return 0, err
	}
	defer release()
	if writer, ok := entry.Resource.(OwnedChunkWriter); ok {
		n, err := writer.WriteOwnedChunk(ctx, owner, source, flags)
		if entry.isClosed() {
			return 0, ErrResourceClosed
		}
		if n < 0 || n > len(source) || err == nil && n != len(source) {
			return 0, io.ErrShortWrite
		}
		return n, err
	}
	if writer, ok := entry.Resource.(ChunkWriter); ok {
		n, err := writer.WriteChunk(ctx, source, flags)
		if entry.isClosed() {
			return 0, ErrResourceClosed
		}
		if n < 0 || n > len(source) || err == nil && n != len(source) {
			return 0, io.ErrShortWrite
		}
		return n, err
	}
	if flags != 0 {
		return 0, ErrInvalidHandle
	}
	writer, ok := entry.Resource.(io.Writer)
	if !ok {
		return 0, ErrInvalidHandle
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	n, err := writer.Write(source)
	if entry.isClosed() {
		return 0, ErrResourceClosed
	}
	if err == nil && n != len(source) {
		return n, io.ErrShortWrite
	}
	return n, err
}

func (table *Table) Seek(id HandleID, owner Owner, offset int64, whence int) (int64, error) {
	entry, release, err := table.acquire(id, owner, false)
	if err != nil {
		return 0, err
	}
	defer release()
	seeker, ok := entry.Resource.(io.Seeker)
	if !ok {
		return 0, ErrInvalidHandle
	}
	position, err := seeker.Seek(offset, whence)
	if entry.isClosed() {
		return 0, ErrResourceClosed
	}
	return position, err
}

func (table *Table) Use(id HandleID, owner Owner, kind Kind, use func(io.Closer) error) error {
	return table.use(id, owner, kind, false, use)
}

// UseControl serializes control operations without waiting for a blocked read
// or write on a full-duplex resource.
func (table *Table) UseControl(id HandleID, owner Owner, kind Kind, use func(io.Closer) error) error {
	return table.use(id, owner, kind, true, use)
}

func (table *Table) use(id HandleID, owner Owner, kind Kind, control bool, use func(io.Closer) error) error {
	if use == nil {
		return ErrInvalidHandle
	}
	entry, release, err := table.acquireMode(id, owner, operationRead, control)
	if err != nil {
		return err
	}
	defer release()
	if entry.Kind != kind {
		return ErrInvalidHandle
	}
	err = use(entry.Resource)
	if entry.isClosed() {
		return ErrResourceClosed
	}
	return err
}

func (table *Table) Revoke(predicate func(Owner) bool) error {
	if table == nil {
		return nil
	}
	table.mu.Lock()
	entries := make([]*Entry, 0)
	for id, entry := range table.entries {
		if predicate == nil || predicate(entry.Owner) {
			delete(table.entries, id)
			entries = append(entries, entry)
		}
	}
	table.mu.Unlock()
	var joined error
	for _, entry := range entries {
		joined = errors.Join(joined, entry.close())
	}
	return joined
}

func (table *Table) acquire(id HandleID, owner Owner, write bool) (*Entry, func(), error) {
	mode := operationRead
	if write {
		mode = operationWrite
	}
	return table.acquireMode(id, owner, mode, false)
}

type operationMode uint8

const (
	operationRead operationMode = iota + 1
	operationWrite
	operationControl
)

func (table *Table) acquireMode(id HandleID, owner Owner, mode operationMode, control bool) (*Entry, func(), error) {
	if table == nil {
		return nil, nil, ErrResourceClosed
	}
	table.mu.Lock()
	entry, ok := table.entries[id]
	if !ok {
		table.mu.Unlock()
		return nil, nil, ErrResourceClosed
	}
	if !entry.Owner.matches(owner) {
		if entry.Owner.samePrincipal(owner) {
			delete(table.entries, id)
			table.mu.Unlock()
			_ = entry.close()
			return nil, nil, ErrResourceClosed
		}
		table.mu.Unlock()
		return nil, nil, ErrOwnerMismatch
	}
	table.mu.Unlock()
	if control {
		mode = operationControl
	}
	release := entry.lockOperation(mode)
	if entry.isClosed() {
		release()
		return nil, nil, ErrResourceClosed
	}
	return entry, release, nil
}

func (entry *Entry) close() error {
	entry.stateMu.Lock()
	if entry.closed {
		entry.stateMu.Unlock()
		return nil
	}
	entry.closed = true
	entry.stateMu.Unlock()
	err := entry.Resource.Close()
	entry.operationMu.Lock()
	entry.operationMu.Unlock()
	entry.readMu.Lock()
	entry.readMu.Unlock()
	entry.writeMu.Lock()
	entry.writeMu.Unlock()
	entry.controlMu.Lock()
	entry.controlMu.Unlock()
	return err
}

func (entry *Entry) lockOperation(mode operationMode) func() {
	if _, fullDuplex := entry.Resource.(FullDuplexResource); !fullDuplex {
		entry.operationMu.Lock()
		return entry.operationMu.Unlock
	}
	switch mode {
	case operationWrite:
		entry.writeMu.Lock()
		return entry.writeMu.Unlock
	case operationControl:
		entry.controlMu.Lock()
		return entry.controlMu.Unlock
	default:
		entry.readMu.Lock()
		return entry.readMu.Unlock
	}
}

func (entry *Entry) isClosed() bool {
	entry.stateMu.Lock()
	defer entry.stateMu.Unlock()
	return entry.closed
}

func (table *Table) Len() int {
	if table == nil {
		return 0
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	return len(table.entries)
}
