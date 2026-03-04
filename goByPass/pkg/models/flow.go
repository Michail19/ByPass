package models

import (
	"time"
)

// FlowKey уникальный идентификатор потока
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// FlowState состояние потока
type FlowState string

const (
	FlowStateNew         FlowState = "new"
	FlowStateEstablished FlowState = "established"
	FlowStateClosing     FlowState = "closing"
	FlowStateClosed      FlowState = "closed"
)

// Flow представляет сетевой поток
type Flow struct {
	Key        FlowKey
	State      FlowState
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastPacket time.Time

	// TCP sequence numbers
	SeqClient uint32
	SeqServer uint32
	AckClient uint32
	AckServer uint32

	// Статистика
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64

	// Метаданные
	Hostname string
	IsTLS    bool
	IsHTTP   bool
}

// ToMap конвертирует в map для JSON
func (f *Flow) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"key":         f.Key,
		"state":       f.State,
		"created":     f.CreatedAt,
		"updated":     f.UpdatedAt,
		"packets_in":  f.PacketsIn,
		"packets_out": f.PacketsOut,
		"bytes_in":    f.BytesIn,
		"bytes_out":   f.BytesOut,
		"hostname":    f.Hostname,
		"is_tls":      f.IsTLS,
		"is_http":     f.IsHTTP,
	}
}
