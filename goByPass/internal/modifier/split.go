package modifier

import (
	"log"
)

// ApplySplit применяет разбиение пакета с правильной IP-фрагментацией
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int, alignSNI bool) ([][]byte, error) {
	if len(splitPos) == 0 {
		return [][]byte{packet}, nil
	}

	// Проверяем, что пакет достаточно большой
	if len(packet) < 40 {
		log.Printf("DEBUG: Packet too small for split (%d bytes), returning original", len(packet))
		return [][]byte{packet}, nil
	}

	// Проверяем, что это IPv4
	if packet[0]>>4 != 4 {
		log.Printf("DEBUG: Not IPv4, skipping split")
		return [][]byte{packet}, nil
	}

	// Определяем размер фрагмента на основе первой позиции split
	fragmentSize := 40 // минимальный разумный размер
	if len(splitPos) > 0 && splitPos[0] > 40 {
		fragmentSize = splitPos[0]
	}

	// Ограничиваем максимальный размер фрагмента
	if fragmentSize > 1400 {
		fragmentSize = 1400
	}

	log.Printf("DEBUG: Splitting packet of size %d with fragment size %d", len(packet), fragmentSize)

	// Используем правильную IP-фрагментацию
	fragments, err := FragmentIPPacket(packet, fragmentSize)
	if err != nil {
		log.Printf("ERROR: Failed to fragment packet: %v", err)
		return [][]byte{packet}, nil
	}

	if len(fragments) == 0 {
		log.Printf("WARNING: No fragments created, returning original")
		return [][]byte{packet}, nil
	}

	result := make([][]byte, len(fragments))
	validFragments := 0

	for i, frag := range fragments {
		// Проверяем каждый фрагмент
		if len(frag.Data) < 20 {
			log.Printf("WARNING: Fragment %d too short (%d bytes), skipping", i, len(frag.Data))
			continue
		}
		if frag.Data[0]>>4 != 4 {
			log.Printf("WARNING: Fragment %d not IPv4 (version=%d), fixing", i, frag.Data[0]>>4)
			// Пытаемся исправить
			frag.Data[0] = (frag.Data[0] & 0x0F) | 0x40
		}
		result[validFragments] = frag.Data
		validFragments++

		log.Printf("DEBUG: Fragment %d OK: size=%d, version=%d, offset=%d, more=%v",
			i, len(frag.Data), frag.Data[0]>>4, frag.Offset, frag.MoreFragments)
	}

	if validFragments == 0 {
		log.Printf("ERROR: No valid fragments created")
		return [][]byte{packet}, nil
	}

	return result[:validFragments], nil
}

// SplitAtPosition разбивает пакет в указанной позиции
func SplitAtPosition(packet []byte, pos int) [][]byte {
	if pos <= 0 || pos >= len(packet) {
		return [][]byte{packet}
	}

	return [][]byte{
		packet[:pos],
		packet[pos:],
	}
}

// SplitAfterBytes разбивает после первого вхождения байта
func SplitAfterBytes(packet []byte, b byte) [][]byte {
	for i, v := range packet {
		if v == b {
			return SplitAtPosition(packet, i+1)
		}
	}
	return [][]byte{packet}
}
