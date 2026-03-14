package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ProtocolType определяет тип протокола
type ProtocolType int

const (
	ProtocolUnknown ProtocolType = iota
	ProtocolHTTP
	ProtocolTLS
	ProtocolTCP
	ProtocolUDP
	ProtocolQUIC
	ProtocolWebSocket
)

func (p ProtocolType) String() string {
	switch p {
	case ProtocolHTTP:
		return "HTTP"
	case ProtocolTLS:
		return "TLS"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolQUIC:
		return "QUIC"
	case ProtocolWebSocket:
		return "WebSocket"
	default:
		return "Unknown"
	}
}

// ConnectionInfo хранит информацию о соединении
type ConnectionInfo struct {
	Protocol          ProtocolType
	SNI               string // Server Name Indication (visible / outer)
	InnerSNI          string // если удалось извлечь из ECH (редко, требует decryption key)
	Host              string // Host заголовок (HTTP)
	Method            string // HTTP метод
	Path              string // HTTP путь
	IsTLS             bool
	IsHTTP            bool
	IsHandshake       bool
	IsQUIC            bool
	IsECH             bool     // Encrypted Client Hello detected
	ALPN              []string // Application-Layer Protocol Negotiation
	PayloadLen        int
	UserAgent         string
	ContentType       string
	FirstDataModified int  // сколько data-пакетов уже модифицировали
	PossibleFragment  bool // пакет выглядит как фрагмент TLS record
}

// Analyzer анализирует пакеты и определяет протокол
type Analyzer struct{}

// NewAnalyzer создает новый анализатор
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze анализирует пакет
func (a *Analyzer) Analyze(packet []byte, srcIP, dstIP string, srcPort, dstPort uint16) (*ConnectionInfo, error) {
	info := &ConnectionInfo{
		PayloadLen: len(packet),
	}

	proto, _, payload, err := parseIPv4Transport(packet)
	if err != nil {
		return info, nil
	}
	info.Protocol = proto

	if len(payload) == 0 {
		return info, nil
	}

	// Транспортный протокол
	if packet[9] == 6 {
		info.Protocol = ProtocolTCP
	} else if packet[9] == 17 {
		info.Protocol = ProtocolUDP
	} else {
		return info, nil
	}

	// Payload
	ipHeaderLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHeaderLen+4 {
		return info, nil
	}

	if info.Protocol == ProtocolTCP {
		tcpHeaderLen := int(packet[ipHeaderLen+12]>>4) * 4
		if len(packet) < ipHeaderLen+tcpHeaderLen {
			return info, nil
		}
		payload = packet[ipHeaderLen+tcpHeaderLen:]
	} else {
		// UDP: поле длины (bytes 4-5 UDP-заголовка) = UDP-header(8) + payload.
		// Используем его как верхнюю границу payload, а не len(packet):
		// если udpLen < len(packet) — хвост это padding/trailer, а не payload.
		// Если udpLen > len(packet) — пакет обрезан, ошибка.
		udpLen := int(binary.BigEndian.Uint16(packet[ipHeaderLen+4:]))
		payloadLen := udpLen - 8 // вычитаем UDP-заголовок
		if payloadLen < 0 {
			return info, nil // некорректный udpLen
		}
		end := ipHeaderLen + 8 + payloadLen
		if end > len(packet) {
			return info, nil // пакет обрезан
		}
		payload = packet[ipHeaderLen+8 : end]
	}
	if len(payload) == 0 {
		// SYN/ACK без данных — hostname не заполнится
		return info, nil
	}

	// Оптимизация: если не handshake — пропуск полного парсинга
	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		info.IsTLS = true
		info.Protocol = ProtocolTLS

		// Если есть только record header или record не несёт ClientHello —
		// всё равно считаем это TLS, но не лезем в ClientHello-парсинг.
		if len(payload) < 9 {
			info.PossibleFragment = true
			return info, nil
		}

		info.IsHandshake = payload[5] == 0x01
		if !info.IsHandshake {
			return info, nil
		}

		// Один путь парсинга вместо набора extract* helper'ов
		if err := a.parseTLS(payload, info); err != nil {
			// fail-open: протокол уже распознан как TLS
			return info, nil
		}

		if len(payload) < 60 {
			info.PossibleFragment = true
		}
		return info, nil
	}

	if isTLSFragment(payload) {
		info.IsTLS = true
		info.IsHandshake = true
		info.PossibleFragment = true
		info.Protocol = ProtocolTLS
		return info, nil
	}

	if looksLikeHTTP(payload) {
		info.Protocol = ProtocolHTTP
		if err := a.parseHTTP(payload, info); err != nil {
			return info, nil
		}
		return info, nil
	}

	if len(payload) >= 17 && proto == ProtocolUDP && (payload[0]&0xC0) == 0xC0 && dstPort == 443 {
		version := binary.BigEndian.Uint32(payload[1:5])
		isKnownQUIC := version == 0x00000001 ||
			version == 0x6b3343cf ||
			(version&0x0F0F0F0F == 0x0A0A0A0A)
		if isKnownQUIC {
			info.IsQUIC = true
			info.Protocol = ProtocolQUIC
		}
	}

	return info, nil
}

// hasECH — проверка наличия Encrypted Client Hello extension
func hasECH(data []byte) bool {
	// Minimum: TLS record header(5) + HandshakeType(1) + length(3) + version(2) + random(32) = 43
	if len(data) < 43 {
		return false
	}

	// Skip TLS record header (5) and handshake header (4)
	pos := 9

	// Skip version (2) + random (32)
	pos += 34

	// Session ID
	if pos >= len(data) {
		return false
	}
	sessionLen := int(data[pos])
	pos += 1 + sessionLen

	// Cipher suites
	if pos+2 > len(data) {
		return false
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen

	// Compression methods
	if pos >= len(data) {
		return false
	}
	compLen := int(data[pos])
	pos += 1 + compLen

	// Extensions length
	if pos+2 > len(data) {
		return false
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2

	end := pos + extTotalLen
	if end > len(data) {
		end = len(data) // clamp — truncated packet, but still walk what we have
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0xfe0d { // ECH extension type
			return true
		}

		// Bounds-check before advancing by extLen
		if pos+extLen > end {
			break
		}
		pos += extLen
	}
	return false
}

// IsTLS — простая проверка
func IsTLS(data []byte) bool {
	return len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03
}

// isTLSFragment определяет что payload — фрагмент TLS ClientHello (#1).
//
// Ситуация: TCP segmentation разбил ClientHello между пакетами.
// Первый пакет содержит record header (16 03 xx xx xx) + начало HandshakeType byte.
// Второй пакет начинается прямо с HandshakeType=0x01 (ClientHello) и его 3-байтовой длины.
//
// Простая эвристика: если
//   - payload[0] == 0x01 (HandshakeType: ClientHello)
//   - payload длина >= 4 (HandshakeType + 3 байта длины)
//   - handshake body length разумный (> 32, < 65535)
//
// это вероятно фрагмент ClientHello body.
// False positives: некоторый двоичный мусор на порту 443 может совпасть,
// но это лучше чем полностью пропустить фрагментированный ClientHello.
func isTLSFragment(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	// HandshakeType: ClientHello = 0x01
	if payload[0] != 0x01 {
		return false
	}
	// 3-байтовая длина handshake body
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	// ClientHello body минимум ~38 байт, максимум ~16000 байт
	return hsLen >= 38 && hsLen <= 16000
}

func parseIPv4Transport(packet []byte) (proto ProtocolType, ipHeaderLen int, payload []byte, err error) {
	if len(packet) < 20 {
		return ProtocolUnknown, 0, nil, errors.New("packet too short")
	}
	if packet[0]>>4 != 4 {
		return ProtocolUnknown, 0, nil, errors.New("not IPv4")
	}

	ipHeaderLen = int(packet[0]&0x0F) * 4
	if ipHeaderLen < 20 || ipHeaderLen > 60 || len(packet) < ipHeaderLen {
		return ProtocolUnknown, 0, nil, errors.New("invalid IPv4 header length")
	}

	switch packet[9] {
	case 6: // TCP
		if len(packet) < ipHeaderLen+20 {
			return ProtocolTCP, ipHeaderLen, nil, errors.New("truncated TCP header")
		}
		tcpHeaderLen := int(packet[ipHeaderLen+12]>>4) * 4
		if tcpHeaderLen < 20 || tcpHeaderLen > 60 || len(packet) < ipHeaderLen+tcpHeaderLen {
			return ProtocolTCP, ipHeaderLen, nil, errors.New("invalid TCP header length")
		}
		return ProtocolTCP, ipHeaderLen, packet[ipHeaderLen+tcpHeaderLen:], nil

	case 17: // UDP
		if len(packet) < ipHeaderLen+8 {
			return ProtocolUDP, ipHeaderLen, nil, errors.New("truncated UDP header")
		}
		udpLen := int(binary.BigEndian.Uint16(packet[ipHeaderLen+4 : ipHeaderLen+6]))
		if udpLen < 8 {
			return ProtocolUDP, ipHeaderLen, nil, errors.New("invalid UDP length")
		}
		end := ipHeaderLen + udpLen
		if end > len(packet) {
			return ProtocolUDP, ipHeaderLen, nil, errors.New("truncated UDP payload")
		}
		return ProtocolUDP, ipHeaderLen, packet[ipHeaderLen+8 : end], nil

	default:
		return ProtocolUnknown, ipHeaderLen, nil, nil
	}
}

func looksLikeHTTP(payload []byte) bool {
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
		[]byte("DELETE "), []byte("PATCH "), []byte("OPTIONS "),
		[]byte("CONNECT "), []byte("TRACE "),
	}
	for _, m := range methods {
		if bytes.HasPrefix(payload, m) {
			return true
		}
	}
	return bytes.HasPrefix(payload, []byte("HTTP/"))
}
