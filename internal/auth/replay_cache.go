package auth

import (
	"sync"
	"time"
)

// ReplayCache tracks seen JWT IDs until token expiry.
type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	nowFn   func() time.Time
}

func NewReplayCache(nowFn func() time.Time) *ReplayCache {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &ReplayCache{
		entries: make(map[string]time.Time),
		nowFn:   nowFn,
	}
}

func (c *ReplayCache) SeenOrAdd(jti string, exp time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.nowFn()
	for key, entryExp := range c.entries {
		if !entryExp.After(now) {
			delete(c.entries, key)
		}
	}

	if _, exists := c.entries[jti]; exists {
		return true
	}
	c.entries[jti] = exp
	return false
}
