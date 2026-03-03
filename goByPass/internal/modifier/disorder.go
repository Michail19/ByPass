package modifier

import (
	"encoding/binary"
)

// ApplyDisorder применяет нарушение порядка
func (pm *PacketModifier) ApplyDisorder(packet []byte, disorderPos []int, ttl int) ([][]byte, error) {
	if len(disorderPos) == 0 || ttl <= 0 {
		return nil, nil
	}

	var results [][]byte

	for _, pos := range disorderPos {
		if pos >= len(packet) {
			continue
		}

		// Создаем копию пакета с низким TTL
		disorderPacket := make([]byte, len(packet))
		copy(disorderPacket, packet)

		// Модифицируем IP-заголовок, устанавливая TTL
		if err := setIPTTL(disorderPacket, ttl); err != nil {
			continue
		}

		// Отправляем только часть пакета
		if pos > 0 {
			disorderPacket = disorderPacket[:pos]
		}

		results = append(results, disorderPacket)
	}

	// Добавляем оригинал в конец
	if len(results) > 0 {
		results = append(results, packet)
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
