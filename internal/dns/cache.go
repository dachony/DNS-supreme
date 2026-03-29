package dns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

type Cache struct {
	maxSize int
	entries map[string]*cacheEntry
	mu      sync.RWMutex
}

func NewCache(maxSize int) *Cache {
	c := &Cache{
		maxSize: maxSize,
		entries: make(map[string]*cacheEntry),
	}
	go c.cleanupLoop()
	return c
}

func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	return entry.msg.Copy(), true
}

func (c *Cache) Set(key string, msg *dns.Msg, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &cacheEntry{
		msg:       msg.Copy(),
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	first := true
	for k, v := range c.entries {
		if first || v.expiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.expiresAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}
