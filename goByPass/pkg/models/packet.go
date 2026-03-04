package models

import (
	"net"
	"time"
)

// Packet представляет сетевой пакет
type Packet struct {
	ID        uint32
	Data      []byte
	Length    int
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Interface string
	Timestamp time.Time
	Mark      uint32
}

// PacketInfo содержит разобранную информацию о пакете
type PacketInfo struct {
	IsTLS     bool
	IsHTTP    bool
	SNI       string
	Host      string
	Method    string
	Path      string
	UserAgent string
	JA3       string
	JA3Hash   string
}

// Clone создает копию пакета
func (p *Packet) Clone() *Packet {
	clone := *p
	clone.Data = make([]byte, len(p.Data))
	copy(clone.Data, p.Data)
	return &clone
}

// String возвращает строковое представление
func (p *Packet) String() string {
	return p.SrcIP.String()
}
