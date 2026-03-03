package protocol

import "fmt"

// ConnectionInfo хранит информацию о соединении
type ConnectionInfo struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string // "tcp", "udp"
	Payload  []byte
}

// TLSExtractor извлекает информацию из TLS-рукопожатия
type TLSExtractor struct {
	SNI string // Server Name Indication
	JA3 string // Отпечаток TLS-клиента
}

// HTTPExtractor извлекает информацию из HTTP-запроса
type HTTPExtractor struct {
	Method  string
	Host    string
	Path    string
	Headers map[string]string
}

// AnalyzePayload определяет тип протокола и извлекает данные
func AnalyzePayload(data []byte) (interface{}, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short")
	}

	// Проверяем на TLS ClientHello (0x16)
	if data[0] == 0x16 && (data[1] == 0x03 || data[1] == 0x02) {
		return extractTLSInfo(data)
	}

	// Проверяем на HTTP
	if isHTTP(data) {
		return extractHTTPInfo(data)
	}

	return nil, fmt.Errorf("unknown protocol")
}
