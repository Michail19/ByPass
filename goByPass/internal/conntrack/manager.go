package conntrack

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// Manager управляет всеми потоками
type Manager struct {
	flows     map[FlowKey]*Flow
	mu        sync.RWMutex
	timeout   time.Duration
	maxFlows  int
	closeChan chan struct{}
	stats     ManagerStats
}

// ManagerStats статистика менеджера
type ManagerStats struct {
	TotalFlows   uint64
	ActiveFlows  int
	ExpiredFlows uint64
	CreatedFlows uint64
	Errors       uint64
}

// NewManager создает новый менеджер потоков
func NewManager(timeout time.Duration, maxFlows int) *Manager {
	m := &Manager{
		flows:     make(map[FlowKey]*Flow),
		timeout:   timeout,
		maxFlows:  maxFlows,
		closeChan: make(chan struct{}),
	}

	// Запускаем очистку устаревших потоков
	go m.cleanupLoop()

	return m
}

// Stop останавливает менеджер
func (m *Manager) Stop() {
	close(m.closeChan)
}

// GetOrCreate возвращает существующий поток или создает новый
func (m *Manager) GetOrCreate(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	protocol uint8,
) *Flow {

	key := m.createKey(srcIP, dstIP, srcPort, dstPort, protocol)

	// Пытаемся найти существующий поток
	m.mu.RLock()
	flow, exists := m.flows[key]
	m.mu.RUnlock()

	if exists {
		return flow
	}

	// Создаем новый поток
	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверяем еще раз (race condition)
	if flow, exists = m.flows[key]; exists {
		return flow
	}

	// Проверяем лимит
	if len(m.flows) >= m.maxFlows {
		m.evictOldest()
	}

	flow = NewFlow(key, srcIP.String(), dstIP.String())
	m.flows[key] = flow
	m.stats.CreatedFlows++
	m.stats.TotalFlows++

	return flow
}

// Get возвращает поток по ключу
func (m *Manager) Get(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	protocol uint8,
) (*Flow, bool) {

	key := m.createKey(srcIP, dstIP, srcPort, dstPort, protocol)

	m.mu.RLock()
	flow, exists := m.flows[key]
	m.mu.RUnlock()

	return flow, exists
}

// Delete удаляет поток
func (m *Manager) Delete(key FlowKey) {
	m.mu.Lock()
	delete(m.flows, key)
	m.mu.Unlock()
}

// createKey создает ключ потока из IP адресов и портов
func (m *Manager) createKey(
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	protocol uint8,
) FlowKey {

	var srcUint32, dstUint32 uint32

	// Конвертируем IPv4 в uint32
	if ipv4 := srcIP.To4(); ipv4 != nil {
		srcUint32 = binary.BigEndian.Uint32(ipv4)
	}
	if ipv4 := dstIP.To4(); ipv4 != nil {
		dstUint32 = binary.BigEndian.Uint32(ipv4)
	}

	return FlowKey{
		SrcIP:    srcUint32,
		DstIP:    dstUint32,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: FlowProtocol(protocol),
	}
}

// cleanupLoop периодически удаляет устаревшие потоки
func (m *Manager) cleanupLoop() {
	// Guard against timeout=0: time.NewTicker(0) паникует (#TimeoutZero).
	interval := m.timeout / 10
	if interval <= 0 {
		interval = 5 * time.Second // безопасный дефолт
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.closeChan:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// IsExpired проверяет, истек ли поток
func (f *Flow) IsExpired(timeout time.Duration, now time.Time) bool {
	f.Mu.RLock()
	defer f.Mu.RUnlock()
	return now.Sub(f.UpdatedAt) > timeout
}

// cleanup удаляет потоки, которые не обновлялись дольше timeout
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, flow := range m.flows {
		// Используем метод с блокировкой
		if flow.IsExpired(m.timeout, now) {
			delete(m.flows, key)
			m.stats.ExpiredFlows++
		}
	}

	m.stats.ActiveFlows = len(m.flows)
}

// evictOldest удаляет самый старый поток при переполнении.
// Вызывается только из GetOrCreate под m.mu.Lock() — доступ к m.flows безопасен.
// flow.UpdatedAt читается под flow.Mu.RLock() чтобы избежать data race (#EvictRace):
// cleanupLoop и worker goroutines могут обновлять UpdatedAt без m.mu.
func (m *Manager) evictOldest() {
	var oldestKey FlowKey
	var oldestTime time.Time

	for key, flow := range m.flows {
		flow.Mu.RLock()
		updatedAt := flow.UpdatedAt
		flow.Mu.RUnlock()
		if oldestTime.IsZero() || updatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = updatedAt
		}
	}

	if !oldestTime.IsZero() {
		delete(m.flows, oldestKey)
		m.stats.ExpiredFlows++
	}
}

// GetStats возвращает статистику
func (m *Manager) GetStats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	stats.ActiveFlows = len(m.flows)
	return stats
}

// GetFlows возвращает список всех активных потоков
func (m *Manager) GetFlows() []*Flow {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flows := make([]*Flow, 0, len(m.flows))
	for _, flow := range m.flows {
		flows = append(flows, flow)
	}

	return flows
}
