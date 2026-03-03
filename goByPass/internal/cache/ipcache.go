package cache

import (
	"net"
	"sync"
	"time"
)

// IPCacheEntry запись в кэше IP
type IPCacheEntry struct {
	IP           string
	Hostname     string
	ASN          int
	Country      string
	Hits         int64
	FirstSeen    time.Time
	LastSeen     time.Time
	ShouldBypass bool          // нужно ли применять обход
	StrategyID   int           // ID стратегии для этого IP
	AvgLatency   time.Duration // средняя задержка
	PacketLoss   float64       // процент потерь
	ExpireAt     time.Time
}

// IPCache кэширует информацию об IP-адресах
type IPCache struct {
	entries map[string]*IPCacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
	stats   CacheStats
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

// NewIPCache создает новый IP-кэш
func NewIPCache(ttl time.Duration, maxSize int) *IPCache {
	c := &IPCache{
		entries: make(map[string]*IPCacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}

	// Запускаем очистку
	go c.cleanupLoop()

	return c
}

// Get возвращает запись для IP
func (c *IPCache) Get(ip string) (*IPCacheEntry, bool) {
	c.mu.RLock()
	entry, exists := c.entries[ip]
	c.mu.RUnlock()

	if !exists {
		c.stats.Misses++
		return nil, false
	}

	// Проверяем не устарела ли запись
	if time.Now().After(entry.ExpireAt) {
		c.Delete(ip)
		c.stats.Expired++
		return nil, false
	}

	entry.Hits++
	c.stats.Hits++

	return entry, true
}

// GetByIP получает запись по net.IP
func (c *IPCache) GetByIP(ip net.IP) (*IPCacheEntry, bool) {
	return c.Get(ip.String())
}

// Put добавляет или обновляет запись
func (c *IPCache) Put(ip, hostname string, shouldBypass bool, strategyID int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Проверяем размер кэша
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	now := time.Now()

	if entry, exists := c.entries[ip]; exists {
		// Обновляем существующую запись
		entry.Hits++
		entry.LastSeen = now
		entry.Hostname = hostname
		entry.ShouldBypass = shouldBypass
		entry.StrategyID = strategyID
		entry.ExpireAt = now.Add(c.ttl)
	} else {
		// Создаем новую запись
		c.entries[ip] = &IPCacheEntry{
			IP:           ip,
			Hostname:     hostname,
			Hits:         1,
			FirstSeen:    now,
			LastSeen:     now,
			ShouldBypass: shouldBypass,
			StrategyID:   strategyID,
			ExpireAt:     now.Add(c.ttl),
		}
		c.stats.TotalEntries++
	}
}

// PutByIP добавляет запись по net.IP
func (c *IPCache) PutByIP(ip net.IP, hostname string, shouldBypass bool, strategyID int) {
	c.Put(ip.String(), hostname, shouldBypass, strategyID)
}

// Delete удаляет запись
func (c *IPCache) Delete(ip string) {
	c.mu.Lock()
	delete(c.entries, ip)
	c.mu.Unlock()
}

// UpdateLatency обновляет информацию о задержке
func (c *IPCache) UpdateLatency(ip string, latency time.Duration, loss float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[ip]; exists {
		// Экспоненциальное скользящее среднее
		if entry.AvgLatency == 0 {
			entry.AvgLatency = latency
			entry.PacketLoss = loss
		} else {
			entry.AvgLatency = time.Duration(float64(entry.AvgLatency)*0.7 + float64(latency)*0.3)
			entry.PacketLoss = entry.PacketLoss*0.7 + loss*0.3
		}
	}
}

// cleanupLoop периодически удаляет устаревшие записи
func (c *IPCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl / 10)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

// cleanup удаляет устаревшие записи
func (c *IPCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for ip, entry := range c.entries {
		if now.After(entry.ExpireAt) {
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
	c.entries = make(map[string]*IPCacheEntry)
	c.mu.Unlock()
}
