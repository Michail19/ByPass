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
	entries  map[string]*DomainCacheEntry
	mu       sync.RWMutex
	ttl      time.Duration
	maxSize  int
	stats    DomainCacheStats
	stopCh   chan struct{}
	resolver *net.Resolver
	stopOnce sync.Once
}

// DomainCacheStats статистика кэша доменов
type DomainCacheStats struct {
	Size          int
	Hits          uint64
	Misses        uint64
	ResolveCount  uint64
	ResolveErrors uint64
}

// NewDomainCache создает новый кэш доменов.
// FIX #11: если ttl <= 0 — используем defaultCacheTTL вместо передачи 0 в time.NewTicker.
func NewDomainCache(ttl time.Duration, maxSize int) *DomainCache {
	if ttl <= 0 {
		log.Printf("[DomainCache] Warning: invalid TTL %v, using default %v", ttl, defaultCacheTTL)
		ttl = defaultCacheTTL
	}
	if maxSize <= 0 {
		maxSize = 5000
	}

	c := &DomainCache{
		entries:  make(map[string]*DomainCacheEntry),
		ttl:      ttl,
		maxSize:  maxSize,
		stopCh:   make(chan struct{}),
		resolver: net.DefaultResolver,
	}

	go c.cleanupLoop()

	return c
}

// Get возвращает запись для домена
func (c *DomainCache) Get(domain string) (*DomainCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[domain]
	if !exists {
		c.stats.Misses++
		return nil, false
	}

	now := time.Now()
	if now.After(entry.ExpireAt) {
		delete(c.entries, domain)
		c.stats.Misses++
		return nil, false
	}

	entry.LastSeen = now
	c.stats.Hits++

	cp := &DomainCacheEntry{
		Domain:      entry.Domain,
		IPs:         append([]net.IP(nil), entry.IPs...),
		CNAME:       entry.CNAME,
		FirstSeen:   entry.FirstSeen,
		LastSeen:    entry.LastSeen,
		ExpireAt:    entry.ExpireAt,
		ResolveTime: entry.ResolveTime,
		TTL:         entry.TTL,
	}
	return cp, true
}

// Resolve разрешает домен в IP (с кэшированием и таймаутом)
func (c *DomainCache) Resolve(domain string) ([]net.IP, error) {
	if entry, exists := c.Get(domain); exists {
		return entry.IPs, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()

	ips, err := c.resolver.LookupIPAddr(ctx, domain)
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

	now := time.Now()

	if entry, exists := c.entries[domain]; exists {
		entry.IPs = append([]net.IP(nil), ips...)
		entry.CNAME = cname
		entry.LastSeen = now
		entry.ExpireAt = now.Add(c.ttl)
		entry.ResolveTime = resolveTime
		return
	}

	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[domain] = &DomainCacheEntry{
		Domain:      domain,
		IPs:         append([]net.IP(nil), ips...),
		CNAME:       cname,
		FirstSeen:   now,
		LastSeen:    now,
		ExpireAt:    now.Add(c.ttl),
		ResolveTime: resolveTime,
	}
}

// PutWithTTL добавляет запись с указанным TTL из DNS
func (c *DomainCache) PutWithTTL(domain string, ips []net.IP, cname string, ttl int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	if ttl <= 0 {
		ttl = int(c.ttl / time.Second)
		if ttl <= 0 {
			ttl = 60
		}
	}

	if entry, exists := c.entries[domain]; exists {
		entry.IPs = append([]net.IP(nil), ips...)
		entry.CNAME = cname
		entry.LastSeen = now
		entry.ExpireAt = now.Add(time.Duration(ttl) * time.Second)
		entry.TTL = ttl
		return
	}

	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[domain] = &DomainCacheEntry{
		Domain:    domain,
		IPs:       append([]net.IP(nil), ips...),
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
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

// cleanupLoop периодически очищает кэш.
// FIX: ticker interval = ttl/10, но не менее minCleanupInterval (5s).
// При малых TTL (например 10s) интервал ttl/10 = 1s создаёт лишнюю нагрузку.
func (c *DomainCache) cleanupLoop() {
	interval := c.ttl / 10
	if interval < minCleanupInterval {
		interval = minCleanupInterval
	}
	ticker := time.NewTicker(interval)
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

// evictOldest удаляет самую старую запись при переполнении
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

// Preload предзагружает список доменов (параллельно, до 5 одновременно).
// Вызывается синхронно — горутины для каждого домена запускаются внутри.
// НЕ оборачивать в отдельную go-рутину снаружи: это double goroutine spawn.
func (c *DomainCache) Preload(domains []string) error {
	semaphore := make(chan struct{}, 5)
	var wg sync.WaitGroup

	errCh := make(chan error, len(domains))

	for _, domain := range domains {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(d string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if _, err := c.Resolve(d); err != nil {
				errCh <- err
			}
		}(domain)
	}

	wg.Wait()
	close(errCh)

	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
