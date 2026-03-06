package modifier

import "log"

// ApplySplit применяет разбиение пакета
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int, alignSNI bool) ([][]byte, error) {
	if len(splitPos) == 0 {
		return [][]byte{packet}, nil
	}

	// Проверяем, что пакет достаточно большой
	if len(packet) < 40 {
		log.Printf("DEBUG: Packet too small for split (%d bytes), returning original", len(packet))
		return [][]byte{packet}, nil
	}

	// Проверяем IPv4
	if packet[0]>>4 != 4 {
		log.Printf("DEBUG: Not IPv4, skipping split")
		return [][]byte{packet}, nil
	}

	// Определяем MTU для фрагментации
	mtu := splitPos[0]
	if mtu < 40 {
		mtu = 40
	}
	if mtu > 1400 {
		mtu = 1400
	}

	log.Printf("DEBUG: Splitting packet of size %d with fragment size %d", len(packet), mtu)

	// Фрагментируем пакет
	fragments, err := FragmentIPPacket(packet, mtu)
	if err != nil {
		log.Printf("ERROR: Failed to fragment packet: %v", err)
		return [][]byte{packet}, nil
	}

	result := make([][]byte, 0, len(fragments))
	for _, frag := range fragments {
		result = append(result, frag.Data)
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
