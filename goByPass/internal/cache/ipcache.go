package cache

import (
	"sync"
	"time"
)

// Entry хранит информацию об IP-адресе
type Entry struct {
	IP           string
	Hostname     string
	Hits         int64
	FirstSeen    time.Time
	LastSeen     time.Time
	ShouldBypass bool // нужно ли применять обход к этому IP
	StrategyID   int  // ID стратегии для этого IP
}

// IPCache кэширует информацию об IP-адресах
type IPCache struct {
	entries map[string]*Entry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

func NewIPCache(ttl time.Duration, maxSize int) *IPCache {
	c := &IPCache{
		entries: make(map[string]*Entry),
		ttl:     ttl,
		maxSize: maxSize,
	}
	go c.cleanupLoop()
	return c
}

// Get возвращает запись для IP
func (c *IPCache) Get(ip string) (*Entry, bool) {
	c.mu.RLock()
	entry, exists := c.entries[ip]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Проверяем не устарела ли запись
	if time.Since(entry.LastSeen) > c.ttl {
		c.Delete(ip)
		return nil, false
	}

	return entry, true
}

// Put добавляет или обновляет запись
func (c *IPCache) Put(ip, hostname string, shouldBypass bool, strategyID int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Проверяем размер кэша
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	if entry, exists := c.entries[ip]; exists {
		entry.Hits++
		entry.LastSeen = time.Now()
		entry.Hostname = hostname
		entry.ShouldBypass = shouldBypass
		entry.StrategyID = strategyID
	} else {
		c.entries[ip] = &Entry{
			IP:           ip,
			Hostname:     hostname,
			Hits:         1,
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			ShouldBypass: shouldBypass,
			StrategyID:   strategyID,
		}
	}
}
