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

	// Исходные IP для определения направления
	SrcIPStr string
	DstIPStr string

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

	StrategyID          int
	IsHandshakeModified bool
	reverseDNSPending   bool
	Mu                  sync.RWMutex // single mutex for all fields

	// Новые поля из analyzer.go
	IsECH               bool
	ALPN                []string
	IsAnalyzed          bool // для кэширования анализа
	DataPacketsModified int  // сколько data-пакетов уже модифицировали

	// QUICFakeInjected: fake QUIC Initial уже инжектированы для этого потока (#5).
	// QUIC fake injection нужна только для первых 1-2 пакетов handshake.
	// После этого поток идёт как video streaming — тысячи пакетов.
	// Без этого флага каждый UDP:443 пакет генерирует 6 fake → убивает throughput.
	QUICFakeInjected bool
	AnalyzeMisses    int // сколько payload-пакетов прошло без SNI/Host
}

// NewFlow создает новый поток
func NewFlow(key FlowKey, srcIPStr, dstIPStr string) *Flow {
	return &Flow{
		Key:        key,
		SrcIPStr:   srcIPStr,
		DstIPStr:   dstIPStr,
		State:      FlowStateNew,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		ClientData: make([][]byte, 0, maxReassemblyPackets),
		ServerData: make([][]byte, 0, maxReassemblyPackets),
	}
}

// Максимальный размер буфера для reassembly (например, 10 пакетов)
const maxReassemblyPackets = 10

// Update обновляет состояние потока на основе пакета
func (f *Flow) Update(isClient bool, seq, ack uint32, length int, data []byte) {
	f.Mu.Lock()
	defer f.Mu.Unlock()

	now := time.Now()
	f.UpdatedAt = now
	f.LastPacket = now

	// length может прийти некорректным (< 0), поэтому:
	// 1) для статистики байт зажимаем его в [0..]
	// 2) для копирования payload дополнительно ограничиваем len(data)
	safeLen := length
	if safeLen < 0 {
		safeLen = 0
	}

	copyLen := safeLen
	if data != nil && copyLen > len(data) {
		copyLen = len(data)
	}

	if isClient {
		f.SeqClient = seq
		f.AckClient = ack
		f.PacketsOut++
		f.BytesOut += uint64(safeLen)

		if copyLen > 0 {
			dataCopy := make([]byte, copyLen)
			copy(dataCopy, data[:copyLen])
			f.ClientData = append(f.ClientData, dataCopy)
			// Ограничиваем размер
			if len(f.ClientData) > maxReassemblyPackets {
				// Удаляем самые старые данные
				f.ClientData = f.ClientData[1:]
			}
		}
	} else {
		f.SeqServer = seq
		f.AckServer = ack
		f.PacketsIn++
		f.BytesIn += uint64(safeLen)

		if copyLen > 0 {
			dataCopy := make([]byte, copyLen)
			copy(dataCopy, data[:copyLen])
			f.ServerData = append(f.ServerData, dataCopy)
			if len(f.ServerData) > maxReassemblyPackets {
				f.ServerData = f.ServerData[1:]
			}
		}
	}

	// Обновляем состояние
	if f.State == FlowStateNew && f.PacketsIn > 0 && f.PacketsOut > 0 {
		f.State = FlowStateEstablished
	}
}

// SetHostname устанавливает имя хоста для потока
func (f *Flow) SetHostname(h string) {
	f.Mu.Lock()
	f.Hostname = h
	f.Mu.Unlock()
}

// SetTLS отмечает поток как TLS
func (f *Flow) SetTLS() {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.IsTLS = true
}

// SetHTTP отмечает поток как HTTP
func (f *Flow) SetHTTP() {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.IsHTTP = true
}

// GetInfo возвращает копию информации о потоке
func (f *Flow) GetInfo() map[string]interface{} {
	f.Mu.RLock()
	defer f.Mu.RUnlock()

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
	f.Mu.RLock()
	defer f.Mu.RUnlock()

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, f.Key.DstIP)
	return ip.String()
}

// GetSrcIP возвращает IP источника как строку
func (f *Flow) GetSrcIP() string {
	f.Mu.RLock()
	defer f.Mu.RUnlock()

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, f.Key.SrcIP)
	return ip.String()
}

// GetDstPort возвращает порт назначения
func (f *Flow) GetDstPort() uint16 {
	f.Mu.RLock()
	defer f.Mu.RUnlock()
	return f.Key.DstPort
}

// GetSrcPort возвращает порт источника
func (f *Flow) GetSrcPort() uint16 {
	f.Mu.RLock()
	defer f.Mu.RUnlock()
	return f.Key.SrcPort
}

func (f *Flow) IsReverseDNSPending() bool {
	f.Mu.RLock()
	defer f.Mu.RUnlock()
	return f.reverseDNSPending
}

func (f *Flow) SetReverseDNSPending(pending bool) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.reverseDNSPending = pending
}
