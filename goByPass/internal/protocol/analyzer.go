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
	Protocol    ProtocolType
	SNI         string // Server Name Indication (для TLS)
	Host        string // Host заголовок (для HTTP)
	Method      string // HTTP метод
	Path        string // HTTP путь
	IsTLS       bool
	IsHTTP      bool
	IsHandshake bool
	IsQUIC      bool
	PayloadLen  int
	UserAgent   string // User-Agent заголовок
	ContentType string // Content-Type заголовок
}

// Analyzer анализирует пакеты и определяет протокол
type Analyzer struct{}

// NewAnalyzer создает новый анализатор
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze анализирует пакет и возвращает информацию о соединении
func (a *Analyzer) Analyze(packet []byte, srcIP, dstIP string, srcPort, dstPort uint16) (*ConnectionInfo, error) {
	if len(packet) < 20 {
		return nil, errors.New("packet too short")
	}

	info := &ConnectionInfo{
		PayloadLen: len(packet),
	}

	// 1. Определяем транспортный протокол
	if packet[9] == 6 {
		info.Protocol = ProtocolTCP
	} else if packet[9] == 17 {
		info.Protocol = ProtocolUDP
	} else {
		return info, nil
	}

	// 2. Находим начало payload
	ipHeaderLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHeaderLen+20 {
		return info, nil
	}
	tcpHeaderLen := int(packet[ipHeaderLen+12]>>4) * 4
	payload := packet[ipHeaderLen+tcpHeaderLen:]
	if len(payload) == 0 {
		// SYN/ACK без данных — hostname не заполнится
		return info, nil
	}

	// 3. Определяем протокол по payload
	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		// TLS Handshake или Application Data
		info.IsTLS = true
		info.IsHandshake = payload[5] == 0x01 // ClientHello
		if sni := extractSNI(payload); sni != "" {
			info.SNI = sni
			log.Printf("[Analyzer] Extracted SNI: %s from %s:%d → %s:%d", sni, srcIP, srcPort, dstIP, dstPort)
		}
	} else if bytes.HasPrefix(payload, []byte("GET ")) ||
		bytes.HasPrefix(payload, []byte("POST ")) ||
		bytes.HasPrefix(payload, []byte("HTTP/")) {
		info.IsHTTP = true
		if host := extractHTTPHost(payload); host != "" {
			info.Host = host
			log.Printf("[Analyzer] Extracted HTTP Host: %s", host)
		}
	} else if (payload[0]&0xF0) == 0xC0 && len(payload) > 1 {
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

	pos := 5 // skip TLS record header

	// Handshake type == 1 (ClientHello)
	if data[pos] != 0x01 {
		return ""
	}
	pos += 4 // handshake header

	// Skip version (2) + random (32)
	pos += 34

	// Session ID
	sessionLen := int(data[pos])
	pos += 1 + sessionLen

	// Cipher suites
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen

	// Compression methods
	compLen := int(data[pos])
	pos += 1 + compLen

	// Extensions length
	if pos+2 > len(data) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	end := pos + extLen

	for pos+4 <= end && pos < len(data) {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // server_name
			if pos+2 > len(data) {
				return ""
			}
			//listLen := int(binary.BigEndian.Uint16(data[pos:]))
			pos += 2

			if pos+3 > len(data) {
				return ""
			}
			nameType := data[pos]
			pos += 1
			if nameType == 0 { // host_name
				nameLen := int(binary.BigEndian.Uint16(data[pos:]))
				pos += 2
				if pos+nameLen <= len(data) {
					return string(data[pos : pos+nameLen])
				}
			}
		}
		pos += extDataLen
	}
	return ""
}

// extractHTTPHost — извлечение Host из HTTP
func extractHTTPHost(data []byte) string {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		lowerLine := bytes.ToLower(line)
		if bytes.HasPrefix(lowerLine, []byte("host:")) {
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
