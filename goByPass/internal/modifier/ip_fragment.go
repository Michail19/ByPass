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

// FragmentIPPacket разбивает IP-пакет на фрагменты
func FragmentIPPacket(packet []byte, fragmentSize int) ([]*IPFragment, error) {
	if len(packet) < 20 {
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	// Проверяем, что это IPv4
	version := packet[0] >> 4
	if version != 4 {
		log.Printf("WARNING: Not an IPv4 packet (version=%d), cannot fragment", version)
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
	if totalLen <= ihl {
		log.Printf("WARNING: No data in packet, totalLen=%d, ihl=%d", totalLen, ihl)
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	data := packet[ihl:totalLen]
	dataLen := len(data)

	// Рассчитываем размер данных в каждом фрагменте (должен быть кратен 8 для IPv4)
	fragDataSize := (fragmentSize - ihl) & ^7
	if fragDataSize <= 8 { // Слишком маленький размер
		fragDataSize = 1400 // безопасное значение по умолчанию
		log.Printf("DEBUG: Using default fragment size: %d", fragDataSize)
	}

	log.Printf("DEBUG: Fragmenting packet ID=%d, totalLen=%d, ihl=%d, dataLen=%d, fragSize=%d",
		id, totalLen, ihl, dataLen, fragDataSize)

	var fragments []*IPFragment
	fragOffset := 0

	for fragOffset < dataLen {
		// Размер данных для этого фрагмента
		thisFragSize := fragDataSize
		if fragOffset+thisFragSize > dataLen {
			thisFragSize = dataLen - fragOffset
		}

		// Создаем новый IP-заголовок для фрагмента
		fragHeader := make([]byte, ihl)
		copy(fragHeader, packet[:ihl])

		// Устанавливаем длину фрагмента
		fragTotalLen := ihl + thisFragSize
		binary.BigEndian.PutUint16(fragHeader[2:4], uint16(fragTotalLen))

		// Устанавливаем флаги фрагментации
		moreFrags := 0
		if fragOffset+thisFragSize < dataLen {
			moreFrags = 1
		}
		// Сохраняем оригинальные флаги, кроме флага фрагментации
		fragHeader[6] = (packet[6] & 0xE0) | byte(moreFrags<<5) | byte(fragOffset>>8&0x1F)

		// Устанавливаем смещение фрагмента (в 8-байтовых блоках)
		fragOffsetBytes := fragOffset / 8
		fragHeader[7] = byte(fragOffsetBytes & 0xFF)

		// Пересчитываем контрольную сумму
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
		copy(fragPacket[ihl:], data[fragOffset:fragOffset+thisFragSize])

		// Проверяем созданный фрагмент
		if len(fragPacket) < 20 {
			log.Printf("ERROR: Fragment too short: %d bytes", len(fragPacket))
			continue
		}
		if fragPacket[0]>>4 != 4 {
			log.Printf("ERROR: Fragment has invalid IP version: %d", fragPacket[0]>>4)
		}

		fragments = append(fragments, &IPFragment{
			Data:          fragPacket,
			Offset:        fragOffset,
			MoreFragments: moreFrags == 1,
		})

		log.Printf("DEBUG: Created fragment %d: size=%d, offset=%d, more=%v, version=%d",
			len(fragments)-1, len(fragPacket), fragOffset, moreFrags == 1, fragPacket[0]>>4)

		fragOffset += thisFragSize
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
