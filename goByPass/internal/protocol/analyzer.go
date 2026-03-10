package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"
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
	if len(packet) < 20 {
		return nil, errors.New("packet too short")
	}

	info := &ConnectionInfo{
		PayloadLen: len(packet),
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

	var payload []byte
	if info.Protocol == ProtocolTCP {
		tcpHeaderLen := int(packet[ipHeaderLen+12]>>4) * 4
		if len(packet) < ipHeaderLen+tcpHeaderLen {
			return info, nil
		}
		payload = packet[ipHeaderLen+tcpHeaderLen:]
	} else {
		udpLen := int(binary.BigEndian.Uint16(packet[ipHeaderLen+4:]))
		if len(packet) < ipHeaderLen+8+udpLen {
			return info, nil
		}
		payload = packet[ipHeaderLen+8:]
	}
	if len(payload) == 0 {
		// SYN/ACK без данных — hostname не заполнится
		return info, nil
	}

	// Оптимизация: если не handshake — пропуск полного парсинга
	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		// TLS Handshake или Application Data
		info.IsTLS = true
		info.IsHandshake = payload[5] == 0x01

		if !info.IsHandshake {
			return info, nil // Не handshake — не парсим SNI/ECH и т.д.
		}

		if sni := extractSNI(payload); sni != "" {
			info.SNI = sni
		}

		alpn := extractALPN(payload)
		if len(alpn) > 0 {
			info.ALPN = alpn
		}

		if hasECH(payload) {
			info.IsECH = true
		}

		if len(payload) < 150 && info.IsHandshake {
			info.PossibleFragment = true
		}
	} else if bytes.HasPrefix(payload, []byte("GET ")) ||
		bytes.HasPrefix(payload, []byte("POST ")) ||
		bytes.HasPrefix(payload, []byte("HTTP/")) {
		info.IsHTTP = true

		if host := extractHTTPHost(payload); host != "" {
			info.Host = host
			log.Printf("[Analyzer] Extracted HTTP Host: %s", host)
		}
	} else if len(payload) > 0 && (payload[0]&0xF0) == 0xC0 {
		info.IsQUIC = true
		info.Protocol = ProtocolQUIC
	}

	return info, nil
}

// extractSNI — надёжный парсер SNI из TLS ClientHello
func extractSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}
	pos := 5               // TLS record header = type(1)+version(2)+length(2)
	if data[pos] != 0x01 { // data[5] = HandshakeType: 0x01 = ClientHello
		return ""
	}
	pos += 4 // skip handshake header: type(1)+length(3)

	pos += 34                    // version(2) + random(32)
	sessionLen := int(data[pos]) // legacy session id
	pos += 1 + sessionLen

	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen

	compLen := int(data[pos])
	pos += 1 + compLen

	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	end := pos + extLen
	if end > len(data) {
		return ""
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // server_name
			if pos+5 > end {
				return ""
			}
			pos += 3 // list length(2) + name type(1)
			nameLen := int(binary.BigEndian.Uint16(data[pos:]))
			pos += 2
			if pos+nameLen <= end {
				return string(data[pos : pos+nameLen])
			}
			return ""
		}
		pos += extDataLen
	}
	return ""
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

// extractALPN — извлечение ALPN из extension 0x0010
func extractALPN(data []byte) []string {
	// Аналогично extractSNI, но ищем extType == 16 (0x0010)
	// Реализация опущена для краткости — добавьте по аналогии
	return nil // ← замените на реальный парсинг
}

// extractHTTPHost — извлечение Host из HTTP
func extractHTTPHost(data []byte) string {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		lower := bytes.ToLower(line)
		if bytes.HasPrefix(lower, []byte("host:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				return strings.TrimSpace(string(parts[1]))
			}
		}
	}
	return ""
}

// IsTLS — простая проверка
func IsTLS(data []byte) bool {
	return len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03
}
