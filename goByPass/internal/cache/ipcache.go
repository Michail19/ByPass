package cache

import (
	"log"
	"net"
	"sync"
	"time"
)

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
	entries map[string]*internalEntry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
	stats   CacheStats
	stopCh  chan struct{}
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
		entries: make(map[string]*internalEntry),
		ttl:     ttl,
		maxSize: maxSize,
		stopCh:  make(chan struct{}),
	}

	// Запускаем очистку
	go c.cleanupLoop()

	return c
}

// Stop останавливает очистку кэша
func (c *IPCache) Stop() {
	close(c.stopCh)
}

// Get возвращает копию записи для IP
func (c *IPCache) Get(ip string) (*IPCacheEntry, bool) {
	c.mu.RLock()
	entry, exists := c.entries[ip]
	c.mu.RUnlock()

	if !exists {
		c.updateMisses()
		return nil, false
	}

	if time.Now().After(entry.expireAt) {
		c.Delete(ip)
		c.updateExpired()
		return nil, false
	}

	// Обновляем статистику и возвращаем копию
	c.updateHits(entry)

	return &IPCacheEntry{
		IP:           entry.IP,
		Hostname:     entry.Hostname,
		ShouldBypass: entry.ShouldBypass,
		StrategyID:   entry.StrategyID,
		Hits:         entry.Hits,
		FirstSeen:    entry.FirstSeen,
		LastSeen:     entry.LastSeen,
		AvgLatency:   entry.AvgLatency,
		PacketLoss:   entry.PacketLoss,
	}, true
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
		entry.expireAt = now.Add(c.ttl)
	} else {
		// Создаем новую запись
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

// InvalidateByStrategy удаляет все записи, связанные с указанной стратегией, возвращает количество удалённых записей
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

// UpdateLatency обновляет информацию о задержке
func (c *IPCache) UpdateLatency(ip string, latency time.Duration, loss float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[ip]; exists {
		// Экспоненциальное скользящее среднее с защитой от переполнения
		if entry.AvgLatency == 0 {
			entry.AvgLatency = latency
			entry.PacketLoss = loss
		} else {
			avgLatency := float64(entry.AvgLatency)
			newLatency := float64(latency)
			entry.AvgLatency = time.Duration(avgLatency*0.7 + newLatency*0.3)
			entry.PacketLoss = entry.PacketLoss*0.7 + loss*0.3
		}
	}
}

// cleanupLoop периодически удаляет устаревшие записи
func (c *IPCache) cleanupLoop() {
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

// Вспомогательные методы для обновления статистики с блокировками
func (c *IPCache) updateMisses() {
	c.mu.Lock()
	c.stats.Misses++
	c.mu.Unlock()
}

func (c *IPCache) updateExpired() {
	c.mu.Lock()
	c.stats.Expired++
	c.mu.Unlock()
}

func (c *IPCache) updateHits(entry *internalEntry) {
	c.mu.Lock()
	entry.Hits++
	c.stats.Hits++
	c.mu.Unlock()
}
