package resourceio

// ObjectIdentity includes the creation identity so inode reuse cannot silently
// transfer a persisted resource grant to a different object.
type ObjectIdentity struct {
	Device         uint64 `json:"device"`
	Object         uint64 `json:"object"`
	CreatedSeconds int64  `json:"created_seconds"`
	CreatedNanos   int64  `json:"created_nanos"`
	Directory      bool   `json:"directory"`
}

func (s *Selection) Identity() (ObjectIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateLocked(); err != nil {
		return ObjectIdentity{}, err
	}
	return selectedObjectIdentity(s.file)
}
func selectedIdentityValid(id ObjectIdentity) bool {
	return id.Object != 0 && id.CreatedSeconds != 0 && id.CreatedNanos >= 0 && id.CreatedNanos < 1_000_000_000
}
func ValidateSelectionIdentity(path string, recursive, writable bool, expected ObjectIdentity) (*Selection, error) {
	s, err := OpenSelection(path, recursive, writable)
	if err != nil {
		return nil, err
	}
	actual, err := s.Identity()
	if err != nil || !selectedIdentityValid(expected) || actual != expected {
		s.Close()
		return nil, ErrUnsafeFile
	}
	return s, nil
}
