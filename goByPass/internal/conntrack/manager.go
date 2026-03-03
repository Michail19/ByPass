package conntrack

import (
	"sync"
	"time"
)

// Flow представляет TCP/UDP поток
type Flow struct {
	ID         string // хеш srcIP+dstIP+srcPort+dstPort+proto
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	State      string // NEW, ESTABLISHED, CLOSING
	SeqNum     uint32 // Текущий sequence number
	AckNum     uint32
	WindowSize uint16
	CreatedAt  time.Time
	UpdatedAt  time.Time
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64
	Payloads   [][]byte // Буфер для reassembly
	mu         sync.RWMutex
}

// Manager управляет всеми потоками
type Manager struct {
	flows    map[string]*Flow
	mu       sync.RWMutex
	timeout  time.Duration
	maxFlows int
}

func NewManager(timeout time.Duration, maxFlows int) *Manager {
	m := &Manager{
		flows:    make(map[string]*Flow),
		timeout:  timeout,
		maxFlows: maxFlows,
	}

	// Запускаем очистку устаревших потоков
	go m.cleanupLoop()
	return m
}

// GetOrCreate возвращает существующий поток или создает новый
func (m *Manager) GetOrCreate(srcIP, dstIP string, srcPort, dstPort uint16, protocol string) *Flow {
	id := flowID(srcIP, dstIP, srcPort, dstPort, protocol)

	m.mu.RLock()
	flow, exists := m.flows[id]
	m.mu.RUnlock()

	if exists {
		return flow
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверяем еще раз (race condition)
	if flow, exists = m.flows[id]; exists {
		return flow
	}

	flow = &Flow{
		ID:        id,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		State:     "NEW",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	m.flows[id] = flow
	return flow
}
