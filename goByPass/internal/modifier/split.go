package modifier

import (
	"ByPass/internal/protocol"
)

// ApplySplit применяет разбиение пакета
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int, alignSNI bool) ([][]byte, error) {
	if len(splitPos) == 0 {
		return [][]byte{packet}, nil
	}

	// Минимальный размер фрагмента - 20 байт (минимальный IP-пакет)
	const minFragmentSize = 20

	var fragments [][]byte
	data := packet

	// Если нужно выравнивание по SNI
	if alignSNI {
		sniPos, err := protocol.FindSNI(packet)
		if err == nil && sniPos >= 0 {
			// Корректируем позиции разбиения относительно SNI
			adjustedPos := make([]int, len(splitPos))
			for i, pos := range splitPos {
				adjustedPos[i] = sniPos + pos
				if adjustedPos[i] < 0 {
					adjustedPos[i] = 0
				}
			}
			splitPos = adjustedPos
		}
	}

	// Применяем разбиение, но проверяем минимальный размер
	lastPos := 0
	for _, pos := range splitPos {
		if pos > lastPos && pos < len(data) {
			// Проверяем, что фрагмент не слишком маленький
			if pos-lastPos < minFragmentSize && len(data)-pos >= minFragmentSize {
				// Пропускаем это разбиение
				continue
			}
			fragments = append(fragments, data[lastPos:pos])
			lastPos = pos
		}
	}

	// Добавляем оставшуюся часть
	if lastPos < len(data) {
		if len(data)-lastPos >= minFragmentSize {
			fragments = append(fragments, data[lastPos:])
		} else {
			// Последний фрагмент слишком маленький - объединяем с предыдущим
			if len(fragments) > 0 {
				lastIdx := len(fragments) - 1
				fragments[lastIdx] = append(fragments[lastIdx], data[lastPos:]...)
			} else {
				fragments = [][]byte{data}
			}
		}
	}

	// Если разбиение не дало результата, возвращаем оригинал
	if len(fragments) == 0 {
		return [][]byte{packet}, nil
	}

	return fragments, nil
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
