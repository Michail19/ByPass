package cache

import (
	"net"
	"sync"
	"time"
)

// DomainCacheEntry запись в кэше доменов
type DomainCacheEntry struct {
	Domain      string
	IPs         []net.IP
	CNAME       string
	FirstSeen   time.Time
	LastSeen    time.Time
	ExpireAt    time.Time
	ResolveTime time.Duration
	TTL         int // оригинальный TTL из DNS
}

// DomainCache кэширует результаты DNS-запросов
type DomainCache struct {
	entries map[string]*DomainCacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
	stats   DomainCacheStats
}

// DomainCacheStats статистика кэша доменов
type DomainCacheStats struct {
	Size          int
	Hits          uint64
	Misses        uint64
	ResolveCount  uint64
	ResolveErrors uint64
}

// NewDomainCache создает новый кэш доменов
func NewDomainCache(ttl time.Duration, maxSize int) *DomainCache {
	c := &DomainCache{
		entries: make(map[string]*DomainCacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}

	go c.cleanupLoop()

	return c
}

// Get возвращает запись для домена
func (c *DomainCache) Get(domain string) (*DomainCacheEntry, bool) {
	c.mu.RLock()
	entry, exists := c.entries[domain]
	c.mu.RUnlock()

	if !exists {
		c.stats.Misses++
		return nil, false
	}

	if time.Now().After(entry.ExpireAt) {
		c.Delete(domain)
		c.stats.Misses++
		return nil, false
	}

	entry.LastSeen = time.Now()
	c.stats.Hits++

	return entry, true
}

// Resolve разрешает домен в IP (с кэшированием)
func (c *DomainCache) Resolve(domain string) ([]net.IP, error) {
	// Проверяем кэш
	if entry, exists := c.Get(domain); exists {
		return entry.IPs, nil
	}

	// Выполняем DNS-запрос
	start := time.Now()
	ips, err := net.LookupIP(domain)
	resolveTime := time.Since(start)

	c.stats.ResolveCount++

	if err != nil {
		c.stats.ResolveErrors++
		return nil, err
	}

	// Сохраняем в кэш
	c.Put(domain, ips, "", resolveTime)

	return ips, nil
}

// Put добавляет запись в кэш
func (c *DomainCache) Put(domain string, ips []net.IP, cname string, resolveTime time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Проверяем размер
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	now := time.Now()

	c.entries[domain] = &DomainCacheEntry{
		Domain:      domain,
		IPs:         ips,
		CNAME:       cname,
		FirstSeen:   now,
		LastSeen:    now,
		ExpireAt:    now.Add(c.ttl),
		ResolveTime: resolveTime,
	}
}

// PutWithTTL добавляет запись с указанным TTL
func (c *DomainCache) PutWithTTL(domain string, ips []net.IP, cname string, ttl int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	c.entries[domain] = &DomainCacheEntry{
		Domain:    domain,
		IPs:       ips,
		CNAME:     cname,
		FirstSeen: now,
		LastSeen:  now,
		ExpireAt:  now.Add(time.Duration(ttl) * time.Second),
		TTL:       ttl,
	}
}

// Delete удаляет запись
func (c *DomainCache) Delete(domain string) {
	c.mu.Lock()
	delete(c.entries, domain)
	c.mu.Unlock()
}

// cleanupLoop периодически очищает кэш
func (c *DomainCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl / 10)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

// cleanup удаляет устаревшие записи
func (c *DomainCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for domain, entry := range c.entries {
		if now.After(entry.ExpireAt) {
			delete(c.entries, domain)
		}
	}
}

// evictOldest удаляет самую старую запись
func (c *DomainCache) evictOldest() {
	var oldestDomain string
	var oldestTime time.Time

	for domain, entry := range c.entries {
		if oldestTime.IsZero() || entry.LastSeen.Before(oldestTime) {
			oldestDomain = domain
			oldestTime = entry.LastSeen
		}
	}

	if oldestDomain != "" {
		delete(c.entries, oldestDomain)
	}
}

// GetStats возвращает статистику
func (c *DomainCache) GetStats() DomainCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.Size = len(c.entries)
	return stats
}

// Preload популярные домены
func (c *DomainCache) Preload(domains []string) error {
	for _, domain := range domains {
		go c.Resolve(domain)
	}
	return nil
}
