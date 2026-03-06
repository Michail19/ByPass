package modifier

import (
	"encoding/binary"
	_ "net"
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

	// Парсим оригинальный IP-заголовок
	ihl := int(packet[0]&0x0F) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	//id := binary.BigEndian.Uint16(packet[4:6])
	//flags := packet[6] >> 5
	//offset := int(binary.BigEndian.Uint16(packet[6:8]) & 0x1FFF) * 8

	// Данные начинаются после заголовка
	data := packet[ihl:totalLen]
	dataLen := len(data)

	// Рассчитываем размер данных в каждом фрагменте (должен быть кратен 8)
	fragDataSize := (fragmentSize - ihl) & ^7
	if fragDataSize <= 0 {
		fragDataSize = 1400 // безопасное значение по умолчанию
	}

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
		fragHeader[6] = packet[6]&0x1F | byte(moreFrags<<5)

		// Устанавливаем смещение фрагмента
		fragOffsetBytes := fragOffset / 8
		binary.BigEndian.PutUint16(fragHeader[6:8], uint16(fragOffsetBytes))

		// Пересчитываем контрольную сумму (обнуляем и вычисляем заново)
		binary.BigEndian.PutUint16(fragHeader[10:12], 0)
		checksum := calculateIPChecksum(fragHeader)
		binary.BigEndian.PutUint16(fragHeader[10:12], checksum)

		// Собираем фрагмент
		fragPacket := make([]byte, fragTotalLen)
		copy(fragPacket[:ihl], fragHeader)
		copy(fragPacket[ihl:], data[fragOffset:fragOffset+thisFragSize])

		fragments = append(fragments, &IPFragment{
			Data:          fragPacket,
			Offset:        fragOffset,
			MoreFragments: moreFrags == 1,
		})

		fragOffset += thisFragSize
	}

	return fragments, nil
}

// calculateIPChecksum вычисляет контрольную сумму IP-заголовка
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
