package cache

import (
	"log"
	"net"
	"sync"
	"time"
)

// defaultCacheTTL используется если TTL не задан или равен нулю.
// FIX #10: time.NewTicker(0) паникует — нужен ненулевой интервал.
const defaultCacheTTL = 30 * time.Minute

// minCleanupInterval — нижний порог для ticker в cleanupLoop.
// При TTL=10s интервал был бы 1s — слишком часто.
// FIX: clamp снизу до 5 секунд.
const minCleanupInterval = 5 * time.Second

// IPCacheEntry запись в кэше IP (неизменяемая копия для внешнего использования)
type IPCacheEntry struct {
	IP           string
	Hostname     string
	ShouldBypass bool
	StrategyID   int
	Hits         int64
	FirstSeen    time.Time
	LastSeen     time.Time
	AvgLatency   time.Duration
	PacketLoss   float64
}

// internalEntry внутреннее представление с дополнительными полями
type internalEntry struct {
	*IPCacheEntry
	expireAt time.Time
}

// IPCache кэширует информацию об IP-адресах
type IPCache struct {
	entries  map[string]*internalEntry
	mu       sync.RWMutex
	ttl      time.Duration
	maxSize  int
	stats    CacheStats
	stopCh   chan struct{}
	stopOnce sync.Once
}

// CacheStats статистика кэша
type CacheStats struct {
	Size         int
	Hits         uint64
	Misses       uint64
	Expired      uint64
	Evictions    uint64
	TotalEntries uint64
}

// NewIPCache создает новый IP-кэш.
// FIX #10: если ttl <= 0 — используем defaultCacheTTL вместо того чтобы передавать 0
// в time.NewTicker (panic: non-positive interval for NewTicker).
func NewIPCache(ttl time.Duration, maxSize int) *IPCache {
	if ttl <= 0 {
		log.Printf("[IPCache] Warning: invalid TTL %v, using default %v", ttl, defaultCacheTTL)
		ttl = defaultCacheTTL
	}
	if maxSize <= 0 {
		maxSize = 10000
	}

	c := &IPCache{
		entries: make(map[string]*internalEntry),
		ttl:     ttl,
		maxSize: maxSize,
		stopCh:  make(chan struct{}),
	}

	go c.cleanupLoop()

	return c
}

// Stop останавливает очистку кэша
func (c *IPCache) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

// Get возвращает копию записи для IP
func (c *IPCache) Get(ip string) (*IPCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[ip]
	if !exists {
		c.stats.Misses++
		return nil, false
	}

	now := time.Now()
	if now.After(entry.expireAt) {
		delete(c.entries, ip)
		c.stats.Expired++
		return nil, false
	}

	entry.Hits++
	entry.LastSeen = now
	c.stats.Hits++

	cp := &IPCacheEntry{
		IP:           entry.IP,
		Hostname:     entry.Hostname,
		ShouldBypass: entry.ShouldBypass,
		StrategyID:   entry.StrategyID,
		Hits:         entry.Hits,
		FirstSeen:    entry.FirstSeen,
		LastSeen:     entry.LastSeen,
		AvgLatency:   entry.AvgLatency,
		PacketLoss:   entry.PacketLoss,
	}
	return cp, true
}

// GetByIP получает запись по net.IP
func (c *IPCache) GetByIP(ip net.IP) (*IPCacheEntry, bool) {
	return c.Get(ip.String())
}

// Put добавляет или обновляет запись
func (c *IPCache) Put(ip, hostname string, shouldBypass bool, strategyID int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	if entry, exists := c.entries[ip]; exists {
		entry.Hits++
		entry.LastSeen = now

		// не затираем точный hostname пустым
		if hostname != "" {
			entry.Hostname = hostname
		}

		// не меняем стратегию на fallback, если уже есть hostname-bound запись
		if !(hostname == "" && entry.Hostname != "" && strategyID != entry.StrategyID) {
			entry.ShouldBypass = shouldBypass
			entry.StrategyID = strategyID
		}

		entry.expireAt = now.Add(c.ttl)
		return
	}

	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[ip] = &internalEntry{
		IPCacheEntry: &IPCacheEntry{
			IP:           ip,
			Hostname:     hostname,
			Hits:         1,
			FirstSeen:    now,
			LastSeen:     now,
			ShouldBypass: shouldBypass,
			StrategyID:   strategyID,
		},
		expireAt: now.Add(c.ttl),
	}
	c.stats.TotalEntries++
}

// PutByIP добавляет запись по net.IP
func (c *IPCache) PutByIP(ip net.IP, hostname string, shouldBypass bool, strategyID int) {
	c.Put(ip.String(), hostname, shouldBypass, strategyID)

	log.Printf("[CACHE] Stored for IP %s: hostname=%s, bypass=%v, strategy=%d",
		ip.String(), hostname, shouldBypass, strategyID)
}

// Delete удаляет запись
func (c *IPCache) Delete(ip string) {
	c.mu.Lock()
	delete(c.entries, ip)
	c.mu.Unlock()
}

// InvalidateByStrategy удаляет все записи с указанной стратегией
func (c *IPCache) InvalidateByStrategy(strategyID int) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for ip, entry := range c.entries {
		if entry.StrategyID == strategyID {
			delete(c.entries, ip)
			count++
		}
	}

	if count > 0 {
		log.Printf("Invalidated %d cache entries for strategy ID %d", count, strategyID)
	}

	return count
}

// UpdateLatency обновляет информацию о задержке (EMA α=0.3)
func (c *IPCache) UpdateLatency(ip string, latency time.Duration, loss float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[ip]; exists {
		if entry.AvgLatency == 0 {
			entry.AvgLatency = latency
			entry.PacketLoss = loss
		} else {
			entry.AvgLatency = time.Duration(float64(entry.AvgLatency)*0.7 + float64(latency)*0.3)
			entry.PacketLoss = entry.PacketLoss*0.7 + loss*0.3
		}
	}
}

// cleanupLoop периодически удаляет устаревшие записи.
// FIX #10: ticker interval = ttl/10, но не менее minCleanupInterval (5s).
// При малых TTL (например 10s) интервал ttl/10 = 1s создаёт лишнюю нагрузку.
func (c *IPCache) cleanupLoop() {
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
func (c *IPCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for ip, entry := range c.entries {
		if now.After(entry.expireAt) {
			delete(c.entries, ip)
			c.stats.Expired++
		}
	}
}

// evictOldest удаляет самую старую запись при переполнении
func (c *IPCache) evictOldest() {
	var oldestIP string
	var oldestTime time.Time

	for ip, entry := range c.entries {
		if oldestTime.IsZero() || entry.LastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = entry.LastSeen
		}
	}

	if oldestIP != "" {
		delete(c.entries, oldestIP)
		c.stats.Evictions++
	}
}

// GetStats возвращает статистику
func (c *IPCache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.Size = len(c.entries)
	return stats
}

// Clear очищает кэш
func (c *IPCache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*internalEntry)
	c.mu.Unlock()
}
