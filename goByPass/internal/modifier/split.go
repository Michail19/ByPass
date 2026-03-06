package modifier

import (
	"log"
)

// ApplySplit применяет разбиение пакета с правильной IP-фрагментацией
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int, alignSNI bool) ([][]byte, error) {
	if len(splitPos) == 0 {
		return [][]byte{packet}, nil
	}

	// Определяем размер фрагмента на основе первой позиции split
	fragmentSize := 20 // минимальный размер
	if len(splitPos) > 0 && splitPos[0] > 20 {
		fragmentSize = splitPos[0]
	}

	// Используем правильную IP-фрагментацию
	fragments, err := FragmentIPPacket(packet, fragmentSize)
	if err != nil {
		log.Printf("ERROR: Failed to fragment packet: %v", err)
		return [][]byte{packet}, nil
	}

	result := make([][]byte, len(fragments))
	for i, frag := range fragments {
		result[i] = frag.Data
		log.Printf("DEBUG: Created fragment %d: size=%d, offset=%d, more=%v",
			i, len(frag.Data), frag.Offset, frag.MoreFragments)
	}

	return result, nil
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
