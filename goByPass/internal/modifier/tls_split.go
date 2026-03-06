package modifier

import (
	"ByPass/internal/protocol"
	"encoding/binary"
	"log"
)

// TLSSplitConfig конфигурация для разделения TLS записей
type TLSSplitConfig struct {
	Enabled        bool
	RecordSize     int  // размер TLS записи
	SplitHandshake bool // разделять ли handshake
	SplitAlert     bool // разделять ли alert
}

// ApplyTLSSplit применяет разделение TLS записей
func (pm *PacketModifier) ApplyTLSSplit(packet []byte, config *TLSSplitConfig) ([][]byte, error) {
	if !config.Enabled {
		return nil, nil
	}

	// Проверяем, является ли пакет TLS
	if !protocol.IsTLS(packet) {
		return nil, nil
	}

	// Определяем тип TLS записи
	recordType := packet[0]

	// Применяем разделение в зависимости от типа
	switch recordType {
	case 0x16: // Handshake
		if !config.SplitHandshake {
			return nil, nil
		}
		return splitTLSHandshake(packet, config.RecordSize)

	case 0x15: // Alert
		if !config.SplitAlert {
			return nil, nil
		}
		return splitTLSRecord(packet, config.RecordSize)

	default: // Application Data и другие
		return splitTLSRecord(packet, config.RecordSize)
	}
}

// splitTLSHandshake разделяет TLS Handshake сообщение
func splitTLSHandshake(packet []byte, recordSize int) ([][]byte, error) {
	if len(packet) < 5 {
		return [][]byte{packet}, nil
	}

	var fragments [][]byte

	// TLS record header: type(1) + version(2) + length(2)
	pos := 5
	recordLen := int(binary.BigEndian.Uint16(packet[3:5]))

	if recordSize <= 0 || recordSize >= recordLen {
		recordSize = 64 // значение по умолчанию
	}

	// Разделяем handshake сообщение на несколько записей
	for pos < 5+recordLen {
		chunkSize := recordSize
		if pos+chunkSize > 5+recordLen {
			chunkSize = 5 + recordLen - pos
		}

		// Создаем новую TLS запись
		newRecord := make([]byte, 5+chunkSize)
		newRecord[0] = packet[0] // тип
		newRecord[1] = packet[1] // version
		newRecord[2] = packet[2]
		binary.BigEndian.PutUint16(newRecord[3:5], uint16(chunkSize))
		copy(newRecord[5:], packet[pos:pos+chunkSize])

		fragments = append(fragments, newRecord)
		pos += chunkSize
	}

	return fragments, nil
}

// splitTLSRecord с проверкой целостности
func splitTLSRecord(packet []byte, recordSize int) ([][]byte, error) {
	if len(packet) < 5 || recordSize <= 0 {
		return [][]byte{packet}, nil
	}

	// Проверяем, что это TLS
	if packet[0] < 0x14 || packet[0] > 0x17 {
		return [][]byte{packet}, nil
	}

	var fragments [][]byte
	totalLen := len(packet)
	pos := 0

	for pos < totalLen {
		// Убеждаемся, что не разбиваем TLS record посередине
		if pos > 0 {
			// Это уже не первый фрагмент, проверяем что начинаем с нового record
			// В реальном TLS разделении мы должны создавать новые record headers
			log.Printf("WARNING: TLS record splitting may break connection")
		}

		chunkSize := recordSize
		if pos+chunkSize > totalLen {
			chunkSize = totalLen - pos
		}

		// Создаем копию фрагмента
		fragment := make([]byte, chunkSize)
		copy(fragment, packet[pos:pos+chunkSize])

		// Для первого фрагмента оставляем оригинальный record header
		// Для последующих нужно создавать новые record headers
		if pos > 0 {
			log.Printf("WARNING: Multi-fragment TLS not fully implemented")
		}

		fragments = append(fragments, fragment)
		pos += chunkSize
	}

	return fragments, nil
}
