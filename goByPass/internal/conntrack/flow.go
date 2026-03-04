package conntrack

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// FlowState представляет состояние TCP потока
type FlowState int

const (
	FlowStateNew FlowState = iota
	FlowStateEstablished
	FlowStateClosing
	FlowStateClosed
	FlowStateError
)

func (s FlowState) String() string {
	switch s {
	case FlowStateNew:
		return "NEW"
	case FlowStateEstablished:
		return "ESTABLISHED"
	case FlowStateClosing:
		return "CLOSING"
	case FlowStateClosed:
		return "CLOSED"
	case FlowStateError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// FlowProtocol тип протокола
type FlowProtocol uint8

const (
	ProtocolTCP FlowProtocol = 6
	ProtocolUDP FlowProtocol = 17
)

func (p FlowProtocol) String() string {
	switch p {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO(%d)", p)
	}
}

// FlowKey уникальный идентификатор потока
type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol FlowProtocol
}

func (k FlowKey) String() string {
	srcIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(srcIP, k.SrcIP)
	dstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(dstIP, k.DstIP)

	return fmt.Sprintf("%s:%d-%s:%d/%s",
		srcIP, k.SrcPort, dstIP, k.DstPort, k.Protocol)
}

// FlowPacket информация о пакете в потоке
type FlowPacket struct {
	Seq       uint32
	Ack       uint32
	Len       int
	Data      []byte
	Timestamp time.Time
}

// Flow представляет сетевой поток
type Flow struct {
	Key        FlowKey
	State      FlowState
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastPacket time.Time

	// TCP specific
	SeqClient uint32 // последний sequence number от клиента
	SeqServer uint32 // последний sequence number от сервера
	AckClient uint32 // последний ack от клиента
	AckServer uint32 // последний ack от сервера

	// Статистика
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64

	// Буфер для reassembly
	ClientData [][]byte
	ServerData [][]byte

	// Метаданные
	Hostname string // из SNI или Host
	IsTLS    bool
	IsHTTP   bool

	mu sync.RWMutex
}

// NewFlow создает новый поток
func NewFlow(key FlowKey) *Flow {
	return &Flow{
		Key:       key,
		State:     FlowStateNew,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Update обновляет состояние потока на основе пакета
func (f *Flow) Update(isClient bool, seq, ack uint32, length int, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.UpdatedAt = time.Now()
	f.LastPacket = time.Now()

	if isClient {
		f.SeqClient = seq
		f.AckClient = ack
		f.PacketsOut++
		f.BytesOut += uint64(length)
		if length > 0 && data != nil {
			f.ClientData = append(f.ClientData, data)
		}
	} else {
		f.SeqServer = seq
		f.AckServer = ack
		f.PacketsIn++
		f.BytesIn += uint64(length)
		if length > 0 && data != nil {
			f.ServerData = append(f.ServerData, data)
		}
	}

	// Обновляем состояние
	if f.State == FlowStateNew && f.PacketsIn > 0 && f.PacketsOut > 0 {
		f.State = FlowStateEstablished
	}
}

// SetHostname устанавливает имя хоста для потока
func (f *Flow) SetHostname(hostname string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Hostname = hostname
}

// SetTLS отмечает поток как TLS
func (f *Flow) SetTLS() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.IsTLS = true
}

// SetHTTP отмечает поток как HTTP
func (f *Flow) SetHTTP() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.IsHTTP = true
}

// GetInfo возвращает копию информации о потоке
func (f *Flow) GetInfo() map[string]interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return map[string]interface{}{
		"key":         f.Key.String(),
		"state":       f.State.String(),
		"created":     f.CreatedAt,
		"updated":     f.UpdatedAt,
		"last_packet": f.LastPacket,
		"packets_in":  f.PacketsIn,
		"packets_out": f.PacketsOut,
		"bytes_in":    f.BytesIn,
		"bytes_out":   f.BytesOut,
		"hostname":    f.Hostname,
		"is_tls":      f.IsTLS,
		"is_http":     f.IsHTTP,
	}
}

// GetDstIP возвращает IP назначения как строку
func (f *Flow) GetDstIP() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, f.Key.DstIP)
	return ip.String()
}

// GetSrcIP возвращает IP источника как строку
func (f *Flow) GetSrcIP() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, f.Key.SrcIP)
	return ip.String()
}

// GetDstPort возвращает порт назначения
func (f *Flow) GetDstPort() uint16 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Key.DstPort
}

// GetSrcPort возвращает порт источника
func (f *Flow) GetSrcPort() uint16 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Key.SrcPort
}
