package cache

import (
	"context"
	"log"
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
	stopCh  chan struct{}
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
		stopCh:  make(chan struct{}),
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
		c.mu.Lock()
		c.stats.Misses++
		c.mu.Unlock()
		return nil, false
	}

	if time.Now().After(entry.ExpireAt) {
		c.Delete(domain)
		c.mu.Lock()
		c.stats.Misses++
		c.mu.Unlock()
		return nil, false
	}

	// Update LastSeen and stats under write lock to avoid races
	c.mu.Lock()
	entry.LastSeen = time.Now()
	c.stats.Hits++
	c.mu.Unlock()

	return entry, true
}

// Resolve разрешает домен в IP (с кэшированием и таймаутом)
func (c *DomainCache) Resolve(domain string) ([]net.IP, error) {
	// Проверяем кэш
	if entry, exists := c.Get(domain); exists {
		return entry.IPs, nil
	}

	// Создаем контекст с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	start := time.Now()

	ips, err := resolver.LookupIPAddr(ctx, domain)
	resolveTime := time.Since(start)

	c.mu.Lock()
	c.stats.ResolveCount++
	c.mu.Unlock()

	if err != nil {
		c.mu.Lock()
		c.stats.ResolveErrors++
		c.mu.Unlock()
		return nil, err
	}

	result := make([]net.IP, len(ips))
	for i, ip := range ips {
		result[i] = ip.IP
	}

	c.Put(domain, result, "", resolveTime)
	return result, nil
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

// Stop останавливает фоновую очистку кэша
func (c *DomainCache) Stop() {
	close(c.stopCh)
}

// cleanupLoop периодически очищает кэш
func (c *DomainCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl / 10)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanup()
		}
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
	semaphore := make(chan struct{}, 5) // Максимум 5 одновременных запросов

	for _, domain := range domains {
		semaphore <- struct{}{}
		go func(d string) {
			defer func() { <-semaphore }()
			_, err := c.Resolve(d)
			if err != nil {
				log.Printf("Failed to preload domain %s: %v", d, err)
			}
		}(domain)
	}
	return nil
}
