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
	if len(destination) == 0 || len(destination) > 64<<10 {
		return 0, ErrResourceLimit
	}
	entry, err := table.acquire(id, owner)
	if err != nil {
		return 0, err
	}
	defer entry.operationMu.Unlock()
	reader, ok := entry.Resource.(io.Reader)
	if !ok {
		return 0, ErrInvalidHandle
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	n, err := reader.Read(destination)
	if entry.isClosed() {
		return 0, ErrResourceClosed
	}
	return n, err
}

func (table *Table) Write(ctx context.Context, id HandleID, owner Owner, source []byte) (int, error) {
	if len(source) > 64<<10 {
		return 0, ErrResourceLimit
	}
	entry, err := table.acquire(id, owner)
	if err != nil {
		return 0, err
	}
	defer entry.operationMu.Unlock()
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
	entry, err := table.acquire(id, owner)
	if err != nil {
		return 0, err
	}
	defer entry.operationMu.Unlock()
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

func (table *Table) acquire(id HandleID, owner Owner) (*Entry, error) {
	if table == nil {
		return nil, ErrResourceClosed
	}
	table.mu.Lock()
	entry, ok := table.entries[id]
	if !ok {
		table.mu.Unlock()
		return nil, ErrResourceClosed
	}
	if !entry.Owner.matches(owner) {
		if entry.Owner.samePrincipal(owner) {
			delete(table.entries, id)
			table.mu.Unlock()
			_ = entry.close()
			return nil, ErrResourceClosed
		}
		table.mu.Unlock()
		return nil, ErrOwnerMismatch
	}
	entry.operationMu.Lock()
	table.mu.Unlock()
	if entry.isClosed() {
		entry.operationMu.Unlock()
		return nil, ErrResourceClosed
	}
	return entry, nil
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
	return err
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
