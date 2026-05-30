package control

import (
	"sync"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// MemStore は Store のスレッドセーフなインメモリ実装。
type MemStore struct {
	mu sync.RWMutex
	m  map[srpolicy.Key]srpolicy.Policy
}

// NewMemStore は空の MemStore を返す。
func NewMemStore() *MemStore {
	return &MemStore{m: make(map[srpolicy.Key]srpolicy.Policy)}
}

func (s *MemStore) Get(key srpolicy.Key) (srpolicy.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.m[key]
	return p, ok
}

func (s *MemStore) Put(p srpolicy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[p.Key()] = p
}

func (s *MemStore) Delete(key srpolicy.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}
