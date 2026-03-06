package modifier

import (
	"encoding/binary"
)

// ApplyDisorder применяет нарушение порядка (отправка части пакета с низким TTL)
func (pm *PacketModifier) ApplyDisorder(packet []byte, disorderPos []int, ttl int) ([][]byte, error) {
	if len(disorderPos) == 0 || ttl <= 0 {
		return nil, nil
	}

	var results [][]byte

	for _, pos := range disorderPos {
		if pos <= 0 || pos >= len(packet) {
			continue
		}

		// Создаем копию первой части с низким TTL
		firstPart := make([]byte, pos)
		copy(firstPart, packet[:pos])

		// Устанавливаем TTL
		if err := setIPTTL(firstPart, ttl); err == nil {
			results = append(results, firstPart)
		}

		// Вторая часть (оригинал или с пересчитанной checksum)
		secondPart := make([]byte, len(packet)-pos)
		copy(secondPart, packet[pos:])

		// Для второй части нужно пересчитать TCP checksum
		if len(secondPart) >= 40 {
			FixTCPChecksum(secondPart)
		}
		results = append(results, secondPart)
	}

	return results, nil
}

// setIPTTL изменяет TTL в IP-заголовке
func setIPTTL(packet []byte, ttl int) error {
	if len(packet) < 20 {
		return nil // не IP пакет
	}

	// Проверяем версию IP
	version := packet[0] >> 4
	if version != 4 {
		return nil // пока только IPv4
	}

	// TTL находится в байте 8 IPv4 заголовка
	if len(packet) > 8 {
		packet[8] = byte(ttl)
		// Пересчитываем контрольную сумму
		recalculateIPChecksum(packet)
	}

	return nil
}

// recalculateIPChecksum пересчитывает контрольную сумму IP-заголовка
func recalculateIPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Обнуляем текущую контрольную сумму
	packet[10] = 0
	packet[11] = 0

	// Вычисляем новую
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(packet[10:12], checksum)
}
