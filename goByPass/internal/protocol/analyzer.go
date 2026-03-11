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
		// TLS Handshake или Application Data
		info.IsTLS = true
		info.IsHandshake = len(payload) > 5 && payload[5] == 0x01

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

		if len(payload) < 60 && info.IsHandshake {
			// PossibleFragment: реальный TLS ClientHello ≥ 100-200 байт (extensions + session).
			// Порог 150 (#3) был слишком велик — обычные ClientHello помечались как фрагменты.
			// Порог 60 байт: payload короче 60 не может содержать полный ClientHello
			// (version(2) + random(32) + session + ciphers + exts ≥ 60 байт minimum).
			info.PossibleFragment = true
		}
	} else if isTLSFragment(payload) {
		// Фрагментированный ClientHello (#1): первый пакет содержит только record header
		// без HandshakeType byte, или TCP segmentation разбил ClientHello между пакетами.
		//
		// Пример:
		//   packet1: 16 03 01 02 00   (TLS record header, recordLen=512)
		//   packet2: 01 00 01 f4 ...  (HandshakeType=ClientHello + body)
		//
		// Старая проверка "payload[0]==0x16 && payload[1]==0x03" не ловила packet2.
		// isTLSFragment: проверяет можно ли это быть началом TLS Handshake body.
		//
		// Для таких пакетов:
		//   - IsTLS = true, IsHandshake = true (предположительно)
		//   - SNI извлечь невозможно (нет record header) — hostname будет пустым
		//   - pipeline применит bypass на основе flow.IsTLS уже установленного первым пакетом
		info.IsTLS = true
		info.IsHandshake = true
		info.PossibleFragment = true
	} else if bytes.HasPrefix(payload, []byte("GET ")) ||
		bytes.HasPrefix(payload, []byte("POST ")) ||
		bytes.HasPrefix(payload, []byte("HTTP/")) {
		info.IsHTTP = true

		if host := extractHTTPHost(payload); host != "" {
			info.Host = host
			log.Printf("[Analyzer] Extracted HTTP Host: %s", host)
		}
	} else if len(payload) >= 17 && (payload[0]&0xC0) == 0xC0 && dstPort == 443 {
		// QUIC Long Header: top 2 bits = 11 → (byte & 0xC0) == 0xC0.
		// Маска 0xF0 была неверной — она требовала bits[4..7]=0xC0, пропуская
		// пакеты с type-specific bits != 0 (например, 0xD0, 0xE0, 0xFF).
		//
		// Минимальный размер QUIC Long Header (#2):
		//   1 (flags) + 4 (version) + 1 (DCIL) + 1 (SCIL) + ... ≥ 17 байт.
		//   Проверка len >= 5 давала false positives для DTLS, WireGuard, random UDP.
		//
		// Дополнительная проверка версии снижает false positives с DTLS и random UDP:
		//   QUIC v1       = 0x00000001
		//   QUIC v2       = 0x6b3343cf
		//   QUIC grease   = 0x?a?a?a?a (нижний nibble каждого байта = 0xA)
		version := binary.BigEndian.Uint32(payload[1:5])
		isKnownQUIC := version == 0x00000001 ||
			version == 0x6b3343cf ||
			(version&0x0F0F0F0F == 0x0A0A0A0A) // grease pattern
		if isKnownQUIC {
			info.IsQUIC = true
			info.Protocol = ProtocolQUIC
		}
	}

	return info, nil
}

// extractSNI — надёжный парсер SNI из TLS ClientHello.
// Все продвижения pos проверяются на выход за границы данных (#6).
func extractSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}
	pos := 5
	if data[pos] != 0x01 {
		return ""
	}
	pos += 4  // handshake header
	pos += 34 // version(2) + random(32)

	if pos >= len(data) {
		return ""
	}
	sessionLen := int(data[pos])
	pos++
	if pos+sessionLen > len(data) {
		return ""
	}
	pos += sessionLen

	if pos+2 > len(data) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+cipherLen > len(data) {
		return ""
	}
	pos += cipherLen

	if pos >= len(data) {
		return ""
	}
	compLen := int(data[pos])
	pos++
	if pos+compLen > len(data) {
		return ""
	}
	pos += compLen

	if pos+2 > len(data) {
		return ""
	}
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
		if pos+extDataLen > end {
			return "" // усечённое расширение
		}

		if extType == 0x0000 { // server_name
			// listLen(2) + nameType(1) + nameLen(2) + name
			if extDataLen < 5 {
				return ""
			}
			nameType := data[pos+2]
			if nameType != 0x00 {
				return ""
			}
			nameLen := int(binary.BigEndian.Uint16(data[pos+3:]))
			nameStart := pos + 5
			if nameLen == 0 || nameStart+nameLen > end {
				return ""
			}
			return string(data[nameStart : nameStart+nameLen])
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

// extractALPN — извлечение списка протоколов из ALPN extension (0x0010).
//
// Формат extension data:
//
//	alpnListLen(2) [ protoLen(1) proto(...) ]...
func extractALPN(data []byte) []string {
	if len(data) < 43 {
		return nil
	}
	pos := 5
	if data[pos] != 0x01 {
		return nil
	}
	pos += 4
	pos += 34
	if pos >= len(data) {
		return nil
	}
	sessionLen := int(data[pos])
	pos++
	if pos+sessionLen > len(data) {
		return nil
	}
	pos += sessionLen

	if pos+2 > len(data) {
		return nil
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+cipherLen > len(data) {
		return nil
	}
	pos += cipherLen

	if pos >= len(data) {
		return nil
	}
	compLen := int(data[pos])
	pos++
	if pos+compLen > len(data) {
		return nil
	}
	pos += compLen

	if pos+2 > len(data) {
		return nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	end := pos + extTotalLen
	if end > len(data) {
		return nil
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > end {
			return nil
		}

		if extType == 0x0010 { // ALPN
			if extDataLen < 2 {
				return nil
			}
			alpnListLen := int(binary.BigEndian.Uint16(data[pos:]))
			alpnEnd := pos + 2 + alpnListLen
			if alpnEnd > pos+extDataLen {
				return nil
			}
			cur := pos + 2
			var protos []string
			for cur < alpnEnd {
				protoLen := int(data[cur])
				cur++
				if protoLen == 0 || cur+protoLen > alpnEnd {
					break
				}
				protos = append(protos, string(data[cur:cur+protoLen]))
				cur += protoLen
			}
			return protos
		}
		pos += extDataLen
	}
	return nil
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
