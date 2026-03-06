package modifier

import (
	"encoding/binary"
	"log"
)

// IPFragment представляет фрагментированный IP-пакет
type IPFragment struct {
	Data          []byte
	Offset        int
	MoreFragments bool
}

// FragmentIPPacket разбивает IP-пакет на фрагменты (RFC 791)
func FragmentIPPacket(packet []byte, mtu int) ([]*IPFragment, error) {
	if len(packet) < 20 {
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	// Проверяем IPv4
	if packet[0]>>4 != 4 {
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	// Парсим оригинальный IP-заголовок
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 {
		log.Printf("WARNING: Invalid IP header length: %d", ihl)
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) {
		log.Printf("WARNING: Packet length mismatch: header=%d, actual=%d", totalLen, len(packet))
		// Исправляем длину в заголовке
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		totalLen = len(packet)
	}

	id := binary.BigEndian.Uint16(packet[4:6])

	// Данные начинаются после заголовка
	flags := packet[6] >> 5

	// Данные после заголовка
	if totalLen <= ihl {
		log.Printf("WARNING: No data in packet, totalLen=%d, ihl=%d", totalLen, ihl)
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	data := packet[ihl:totalLen]
	dataLen := len(data)

	// Максимальный размер данных во фрагменте (должен быть кратен 8)
	maxDataSize := (mtu - ihl) & ^7
	if maxDataSize <= 0 {
		maxDataSize = 1400
	}

	log.Printf("DEBUG: Fragmenting packet ID=%d, totalLen=%d, ihl=%d, dataLen=%d, maxDataSize=%d",
		id, totalLen, ihl, dataLen, maxDataSize)

	var fragments []*IPFragment
	offset := 0

	for offset < dataLen {
		// Размер данных для этого фрагмента
		thisDataSize := maxDataSize
		if offset+thisDataSize > dataLen {
			thisDataSize = dataLen - offset
		}

		// Создаем заголовок фрагмента
		fragHeader := make([]byte, ihl)
		copy(fragHeader, packet[:ihl])

		// Устанавливаем длину
		fragTotalLen := ihl + thisDataSize
		binary.BigEndian.PutUint16(fragHeader[2:4], uint16(fragTotalLen))

		// Устанавливаем флаги и смещение
		moreFrags := 0
		if offset+thisDataSize < dataLen {
			moreFrags = 1
		}
		// Смещение в 8-байтовых блоках
		fragOffset := offset / 8
		fragHeader[6] = (flags & 0xE0) | byte(moreFrags<<5) | byte(fragOffset>>8&0x1F)
		fragHeader[7] = byte(fragOffset & 0xFF)

		// Пересчитываем IP checksum
		binary.BigEndian.PutUint16(fragHeader[10:12], 0)
		checksum := calculateIPChecksum(fragHeader)
		binary.BigEndian.PutUint16(fragHeader[10:12], checksum)

		// Проверяем, что версия IP сохранилась
		if fragHeader[0]>>4 != 4 {
			log.Printf("CRITICAL: Fragment header lost IPv4 version! Got %d", fragHeader[0]>>4)
			// Принудительно устанавливаем версию
			fragHeader[0] = (fragHeader[0] & 0x0F) | 0x40
		}

		// Собираем фрагмент
		fragPacket := make([]byte, fragTotalLen)
		copy(fragPacket[:ihl], fragHeader)
		copy(fragPacket[ihl:], data[offset:offset+thisDataSize])

		fragments = append(fragments, &IPFragment{
			Data:          fragPacket,
			Offset:        offset,
			MoreFragments: moreFrags == 1,
		})

		offset += thisDataSize
	}

	return fragments, nil
}

// calculateIPChecksum вычисляет контрольную сумму IP-заголовка
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i+1 >= len(header) {
			sum += uint32(header[i]) << 8
		} else {
			sum += uint32(binary.BigEndian.Uint16(header[i:]))
		}
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
