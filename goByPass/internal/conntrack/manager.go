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

	flow = NewFlow(key)
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
	ticker := time.NewTicker(m.timeout / 10)
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

// cleanup удаляет потоки, которые не обновлялись дольше timeout
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, flow := range m.flows {
		if now.Sub(flow.UpdatedAt) > m.timeout {
			delete(m.flows, key)
			m.stats.ExpiredFlows++
		}
	}

	m.stats.ActiveFlows = len(m.flows)
}

// evictOldest удаляет самый старый поток при переполнении
func (m *Manager) evictOldest() {
	var oldestKey FlowKey
	var oldestTime time.Time

	for key, flow := range m.flows {
		if oldestTime.IsZero() || flow.UpdatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = flow.UpdatedAt
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
