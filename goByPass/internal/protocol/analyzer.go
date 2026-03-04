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
	Protocol    ProtocolType
	SNI         string // Server Name Indication (для TLS)
	Host        string // Host заголовок (для HTTP)
	Method      string // HTTP метод
	Path        string // HTTP путь
	JA3         string // TLS fingerprint
	JA3Hash     string // MD5 хеш JA3
	UserAgent   string // User-Agent
	ContentType string // Content-Type
	IsTLS       bool
	IsHTTP      bool
	IsHandshake bool
	Payload     []byte // первые байты полезной нагрузки
	PayloadLen  int
}

// Analyzer анализирует пакеты и определяет протокол
type Analyzer struct {
	// Кэш для результатов анализа (опционально)
	cache map[string]*ConnectionInfo
}

// NewAnalyzer создает новый анализатор
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		cache: make(map[string]*ConnectionInfo),
	}
}

// Analyze анализирует пакет и возвращает информацию о соединении
func (a *Analyzer) Analyze(packet []byte, srcIP, dstIP string, srcPort, dstPort uint16) (*ConnectionInfo, error) {
	if len(packet) == 0 {
		return nil, errors.New("empty packet")
	}

	info := &ConnectionInfo{
		Payload:    packet,
		PayloadLen: len(packet),
	}

	// Определяем протокол по первым байтам
	info.Protocol = a.detectProtocol(packet)

	// Извлекаем специфичную для протокола информацию
	switch info.Protocol {
	case ProtocolTLS:
		if err := a.parseTLS(packet, info); err != nil {
			// Не фатально, просто не смогли извлечь SNI
		}
	case ProtocolHTTP:
		if err := a.parseHTTP(packet, info); err != nil {
			// Не фатально
		}
	case ProtocolTCP:
		// Ничего не делаем для обычного TCP
	case ProtocolUDP:
		// Ничего не делаем для UDP
	case ProtocolQUIC:
		// TODO: добавить парсинг QUIC
	case ProtocolWebSocket:
		// TODO: добавить парсинг WebSocket
	default:
		// Неизвестный протокол - игнорируем
	}

	return info, nil
}

// detectProtocol определяет протокол по первым байтам пакета
func (a *Analyzer) detectProtocol(data []byte) ProtocolType {
	if len(data) < 2 {
		return ProtocolUnknown
	}

	// Проверка на TLS (0x16 - Handshake, 0x03 - SSL/TLS version)
	if data[0] == 0x16 && (data[1] == 0x03 || data[1] == 0x02 || data[1] == 0x01) {
		return ProtocolTLS
	}

	// Проверка на HTTP методы
	if len(data) >= 4 {
		if bytes.HasPrefix(data, []byte("GET ")) ||
			bytes.HasPrefix(data, []byte("POST ")) ||
			bytes.HasPrefix(data, []byte("HEAD ")) ||
			bytes.HasPrefix(data, []byte("PUT ")) ||
			bytes.HasPrefix(data, []byte("DELETE ")) ||
			bytes.HasPrefix(data, []byte("OPTIONS ")) ||
			bytes.HasPrefix(data, []byte("CONNECT ")) ||
			bytes.HasPrefix(data, []byte("HTTP/")) {
			return ProtocolHTTP
		}
	}

	// Проверка на HTTP ответ
	if len(data) >= 5 {
		if bytes.HasPrefix(data, []byte("HTTP/1.")) ||
			bytes.HasPrefix(data, []byte("HTTP/2.")) ||
			bytes.HasPrefix(data, []byte("HTTP/3.")) {
			return ProtocolHTTP
		}
	}

	// Проверка на QUIC (первые биты: 0b1100xxxx)
	if len(data) >= 1 && (data[0]&0xF0) == 0xC0 {
		return ProtocolQUIC
	}

	// Проверка на WebSocket handshake
	if len(data) >= 20 && bytes.Contains(data, []byte("Upgrade: websocket")) {
		return ProtocolWebSocket
	}

	// По умолчанию возвращаем TCP
	return ProtocolTCP
}

// IsTLS проверяет, является ли пакет TLS
func IsTLS(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	// TLS record types: 0x14-0x17 (ChangeCipherSpec, Alert, Handshake, ApplicationData)
	recordType := data[0]
	if recordType < 0x14 || recordType > 0x17 {
		return false
	}

	// TLS version: 0x0300-0x0304 (SSLv3, TLSv1.0-1.3)
	version := binary.BigEndian.Uint16(data[1:3])
	return version >= 0x0300 && version <= 0x0304
}

// IsHTTP проверяет, является ли пакет HTTP
func IsHTTP(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Проверяем начало запроса
	if bytes.HasPrefix(data, []byte("GET ")) ||
		bytes.HasPrefix(data, []byte("POST ")) ||
		bytes.HasPrefix(data, []byte("HTTP/")) {
		return true
	}

	// Проверяем наличие HTTP заголовков
	return bytes.Contains(data, []byte("HTTP/1.")) ||
		bytes.Contains(data, []byte("HTTP/2."))
}
