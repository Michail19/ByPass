package modifier

import (
	"ByPass/internal/protocol"
	"encoding/binary"
	"log"
)

// TLSSplitConfig конфигурация для разделения TLS записей
type TLSSplitConfig struct {
	Enabled        bool
	RecordSize     int  // желаемый размер каждого фрагмента (рекоменд. 64–128)
	SplitHandshake bool // разделять ClientHello/ServerHello
	SplitAlert     bool // разделять Alert
}

// ApplyTLSSplit применяет разделение TLS записей
func (pm *PacketModifier) ApplyTLSSplit(packet []byte, recordSize int) ([][]byte, error) {
	if recordSize <= 0 || recordSize > 1024 {
		recordSize = 80 // разумное значение по умолчанию
	}

	if len(packet) < 5 || !protocol.IsTLS(packet) {
		return [][]byte{packet}, nil
	}

	// Определяем тип TLS записи
	recordType := packet[0]
	version := binary.BigEndian.Uint16(packet[1:3])
	totalLen := int(binary.BigEndian.Uint16(packet[3:5]))

	if len(packet) != 5+totalLen {
		log.Printf("WARNING: TLS packet length mismatch: header=%d, actual=%d", 5+totalLen, len(packet))
		return [][]byte{packet}, nil
	}

	var fragments [][]byte
	pos := 5 // начало данных после record header

	for pos < len(packet) {
		chunkSize := recordSize
		remaining := len(packet) - pos
		if chunkSize > remaining {
			chunkSize = remaining
		}

		// Создаём новый TLS record
		frag := make([]byte, 5+chunkSize)
		frag[0] = recordType
		binary.BigEndian.PutUint16(frag[1:3], version)
		binary.BigEndian.PutUint16(frag[3:5], uint16(chunkSize))
		copy(frag[5:], packet[pos:pos+chunkSize])

		fragments = append(fragments, frag)
		pos += chunkSize
	}

	if len(fragments) <= 1 {
		log.Printf("DEBUG: TLS split not needed, only 1 fragment")
		return [][]byte{packet}, nil
	}

	log.Printf("DEBUG: TLS record split into %d fragments (size=%d)", len(fragments), recordSize)
	return fragments, nil
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
