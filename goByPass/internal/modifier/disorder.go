package modifier

import (
	"encoding/binary"
)

// ApplyDisorder применяет нарушение порядка (отправка префикса с низким TTL + оригинал)
func (pm *PacketModifier) ApplyDisorder(packet []byte, disorderPos []int, ttl int) ([][]byte, error) {
	if len(disorderPos) == 0 || ttl <= 0 {
		return nil, nil
	}

	var results [][]byte

	for _, pos := range disorderPos {
		if pos <= 0 || pos >= len(packet) {
			continue
		}

		// Проверяем, что это IPv4 пакет
		if len(packet) < 20 || packet[0]>>4 != 4 {
			continue
		}

		ipHeaderLen := int(packet[0]&0x0F) * 4

		// Первая часть должна включать полный IP заголовок
		if pos < ipHeaderLen {
			pos = ipHeaderLen // Минимум - весь IP заголовок
		}

		// Создаем первую часть (с низким TTL)
		firstPart := make([]byte, pos)
		copy(firstPart, packet[:pos])

		// Убеждаемся, что первая часть имеет валидный IP заголовок
		if len(firstPart) >= 20 {
			// Обновляем totalLen
			binary.BigEndian.PutUint16(firstPart[2:4], uint16(pos))

			// Устанавливаем TTL
			if err := setIPTTL(firstPart, ttl); err == nil {
				// Пересчитываем IP checksum
				recalculateIPChecksum(firstPart)

				// Пересчитываем TCP checksum (длина изменилась)
				if packet[9] == 6 { // TCP
					if err := FixTCPChecksum(firstPart); err == nil {
						results = append(results, firstPart)
					}
				} else {
					results = append(results, firstPart)
				}
			}
		}
	}

	// Добавляем оригинал в конец (важно для disorder)
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
