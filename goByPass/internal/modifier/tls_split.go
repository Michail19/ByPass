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
func (pm *PacketModifier) ApplyTLSSplit(packet []byte, splitPos int) ([][]byte, error) {
	if len(packet) < 9 || !protocol.IsTLS(packet) {
		return [][]byte{packet}, nil
	}

	recordType := packet[0]
	version := binary.BigEndian.Uint16(packet[1:3])
	totalLen := int(binary.BigEndian.Uint16(packet[3:5]))
	if len(packet) < 5+totalLen {
		return [][]byte{packet}, nil
	}

	if splitPos <= 0 || splitPos >= totalLen {
		return [][]byte{packet}, nil
	}

	part1 := packet[5 : 5+splitPos]
	part2 := packet[5+splitPos : 5+totalLen]
	tail := packet[5+totalLen:]

	rec1 := make([]byte, 5+len(part1))
	rec1[0] = recordType
	binary.BigEndian.PutUint16(rec1[1:3], version)
	binary.BigEndian.PutUint16(rec1[3:5], uint16(len(part1)))
	copy(rec1[5:], part1)

	// Во второй TCP payload кладём второй record + весь хвост после первого record.
	rec2 := make([]byte, 5+len(part2)+len(tail))
	rec2[0] = recordType
	binary.BigEndian.PutUint16(rec2[1:3], version)
	binary.BigEndian.PutUint16(rec2[3:5], uint16(len(part2)))
	copy(rec2[5:], part2)
	copy(rec2[5+len(part2):], tail)

	return [][]byte{rec1, rec2}, nil
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
