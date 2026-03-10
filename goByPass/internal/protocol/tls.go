package protocol

import (
	_ "bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// TLSVersion представляет версию TLS
type TLSVersion uint16

const (
	TLSVersionSSL30 TLSVersion = 0x0300
	TLSVersionTLS10 TLSVersion = 0x0301
	TLSVersionTLS11 TLSVersion = 0x0302
	TLSVersionTLS12 TLSVersion = 0x0303
	TLSVersionTLS13 TLSVersion = 0x0304
)

func (v TLSVersion) String() string {
	switch v {
	case 0x0300:
		return "SSLv3"
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	case 0x0304:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(v))
	}
}

// TLSRecord представляет TLS запись
type TLSRecord struct {
	Type    uint8
	Version TLSVersion
	Length  uint16
	Data    []byte
}

// TLSExtension представляет TLS расширение
type TLSExtension struct {
	Type   uint16
	Length uint16
	Data   []byte
}

// parseTLS разбирает TLS
func (a *Analyzer) parseTLS(data []byte, info *ConnectionInfo) error {
	if len(data) < 5 {
		return fmt.Errorf("TLS packet too short")
	}

	info.IsTLS = true

	if data[0] == 0x16 {
		info.IsHandshake = true
		return a.parseTLSHandshake(data, info)
	}

	return nil
}

// parseTLSHandshake
func (a *Analyzer) parseTLSHandshake(data []byte, info *ConnectionInfo) error {
	pos := 5
	if pos+4 > len(data) {
		return fmt.Errorf("TLS handshake header too short")
	}

	handshakeType := data[pos]

	if handshakeType != 0x01 {
		return nil
	}
	pos += 4
	return a.parseClientHello(data[pos:], info) // Унифицировано
}

// parseClientHello (унифицировано с extractSNI)
func (a *Analyzer) parseClientHello(data []byte, info *ConnectionInfo) error {
	if len(data) < 38 {
		return fmt.Errorf("ClientHello too short")
	}

	pos := 0
	pos += 2  // version
	pos += 32 // random
	sessionLen := int(data[pos])
	pos += 1 + sessionLen
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen
	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 > len(data) {
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	end := pos + extLen
	if end > len(data) {
		return fmt.Errorf("extensions truncated")
	}
	for pos < end {
		if pos+4 > end {
			break
		}
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > end {
			break
		}
		if extType == 0x0000 { // SNI
			a.parseSNI(data[pos:pos+extDataLen], info)
		}
		if extType == 0x0010 { // ALPN
			a.parseALPN(data[pos:pos+extDataLen], info)
		}
		if extType == 0xfe0d { // ECH
			info.IsECH = true
		}
		pos += extDataLen
	}
	return nil
}

// parseSNI разбирает SNI расширение
func (a *Analyzer) parseSNI(data []byte, info *ConnectionInfo) {
	if len(data) < 3 {
		return
	}

	// Пропускаем список длины
	pos := 2 // list length

	for pos+3 < len(data) {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if nameType == 0x00 && pos+nameLen <= len(data) {
			// nameType 0 - host_name
			info.SNI = string(data[pos : pos+nameLen])
			return
		}
		pos += nameLen
	}
}

// parseALPN разбирает ALPN расширение
func (a *Analyzer) parseALPN(data []byte, info *ConnectionInfo) {
	if len(data) < 2 {
		return
	}

	// ALPN содержит список протоколов
	pos := 2

	for pos < len(data) && pos+1 < len(data) {
		protoLen := int(data[pos])
		pos += 1

		if pos+protoLen <= len(data) {
			proto := string(data[pos : pos+protoLen])
			// Здесь можно сохранить ALPN протоколы
			_ = proto
		}
		pos += protoLen
	}
}

// FindSNI находит позицию SNI в TLS ClientHello
func FindSNI(data []byte) (int, error) {
	if len(data) < 5 || data[0] != 0x16 {
		return -1, fmt.Errorf("not a TLS handshake")
	}

	pos := 5 // пропускаем record header

	// Проверяем handshake type
	if pos >= len(data) || data[pos] != 0x01 {
		return -1, fmt.Errorf("not a ClientHello")
	}
	pos += 4 // пропускаем handshake header

	// Пропускаем version (2)
	pos += 2

	// Пропускаем random (32)
	pos += 32

	// Пропускаем session ID
	if pos >= len(data) {
		return -1, fmt.Errorf("truncated")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Пропускаем cipher suites
	if pos+1 >= len(data) {
		return -1, fmt.Errorf("truncated")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Пропускаем compression methods
	if pos >= len(data) {
		return -1, fmt.Errorf("truncated")
	}
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen

	// Проверяем расширения
	if pos+1 >= len(data) {
		return -1, fmt.Errorf("no extensions")
	}

	// Ищем SNI extension
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	endPos := pos + extensionsLen

	for pos+4 <= endPos && pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // SNI
			// Возвращаем позицию начала имени
			if pos+3 <= len(data) {
				// пропускаем список длины и тип
				sniPos := pos + 3
				if sniPos < len(data) {
					return sniPos, nil
				}
			}
		}
		pos += extLen
	}

	return -1, fmt.Errorf("SNI not found")
}

// CalculateJA3 вычисляет JA3 отпечаток из ClientHello
func CalculateJA3(data []byte, compute bool) (string, string) {
	if !compute {
		return "", ""
	}
	
	if len(data) < 5 || data[0] != 0x16 {
		return "", ""
	}

	pos := 5

	// Проверяем handshake type
	if pos >= len(data) || data[pos] != 0x01 {
		return "", ""
	}
	pos += 4

	// SSL Version
	if pos+1 >= len(data) {
		return "", ""
	}
	version := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Random (пропускаем)
	pos += 32

	// Session ID
	if pos >= len(data) {
		return "", ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+1 >= len(data) {
		return "", ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	var ciphers []uint16
	for i := 0; i < cipherSuitesLen; i += 2 {
		if pos+1 < len(data) {
			cipher := binary.BigEndian.Uint16(data[pos : pos+2])
			ciphers = append(ciphers, cipher)
		}
		pos += 2
	}

	// Compression Methods
	if pos >= len(data) {
		return "", ""
	}
	compMethodsLen := int(data[pos])
	pos += 1
	pos += compMethodsLen

	// Extensions
	var extensions []uint16
	var sigAlgs []uint16
	var groups []uint16
	var formats []uint16

	if pos+1 < len(data) {
		extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		endPos := pos + extensionsLen

		for pos+4 <= endPos && pos+4 <= len(data) {
			extType := binary.BigEndian.Uint16(data[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
			pos += 4

			extensions = append(extensions, extType)

			// Для некоторых расширений сохраняем данные
			if extType == 0x000A { // Supported Groups
				if pos+1 < len(data) {
					groupsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
					for i := 0; i < groupsLen; i += 2 {
						if pos+2+i+1 < len(data) {
							group := binary.BigEndian.Uint16(data[pos+2+i : pos+4+i])
							groups = append(groups, group)
						}
					}
				}
			}

			if extType == 0x000D { // Signature Algorithms
				if pos+1 < len(data) {
					sigAlgsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
					for i := 0; i < sigAlgsLen; i += 2 {
						if pos+2+i+1 < len(data) {
							sigAlg := binary.BigEndian.Uint16(data[pos+2+i : pos+4+i])
							sigAlgs = append(sigAlgs, sigAlg)
						}
					}
				}
			}

			if extType == 0x000B { // EC Point Formats
				if pos < len(data) {
					formatsLen := int(data[pos])
					for i := 0; i < formatsLen; i++ {
						if pos+1+i < len(data) {
							format := uint16(data[pos+1+i])
							formats = append(formats, format)
						}
					}
				}
			}

			pos += extLen
		}
	}

	// Формируем JA3 строку: SSLVersion,Ciphers,Extensions,Groups,Formats
	ja3 := fmt.Sprintf("%d,", version)

	// Ciphers
	for i, c := range ciphers {
		if i > 0 {
			ja3 += "-"
		}
		ja3 += fmt.Sprintf("%d", c)
	}
	ja3 += ","

	// Extensions
	for i, e := range extensions {
		if i > 0 {
			ja3 += "-"
		}
		ja3 += fmt.Sprintf("%d", e)
	}
	ja3 += ","

	// Groups
	for i, g := range groups {
		if i > 0 {
			ja3 += "-"
		}
		ja3 += fmt.Sprintf("%d", g)
	}
	ja3 += ","

	// Formats
	for i, f := range formats {
		if i > 0 {
			ja3 += "-"
		}
		ja3 += fmt.Sprintf("%d", f)
	}

	// Вычисляем MD5 хеш
	hash := md5.Sum([]byte(ja3))
	ja3Hash := hex.EncodeToString(hash[:])

	return ja3, ja3Hash
}
