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
		if packet[9] != 6 { // Не TCP — пропустить
			continue
		}

		tcpHeaderOffset := ipHeaderLen
		tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4
		minPos := ipHeaderLen + tcpHeaderLen // Минимум — полный TCP header

		if pos < minPos {
			continue // Не обрезаем header
		}

		// firstPart до pos (полный header + часть payload)
		firstPart := make([]byte, pos)
		copy(firstPart, packet[:pos])

		// Обновляем totalLen в IP
		binary.BigEndian.PutUint16(firstPart[2:4], uint16(pos))

		// Устанавливаем TTL и пересчитываем IP checksum
		if err := setIPTTL(firstPart, ttl); err == nil {
			// Пересчитываем IP checksum
			recalculateIPChecksum(firstPart)

			// Пересчитываем TCP checksum (поскольку payload обрезан, но header полный)
			if err := FixTCPChecksum(firstPart); err == nil {
				results = append(results, firstPart)
			}
		}
	}

	// Добавляем оригинал
	if len(results) > 0 {
		results = append(results, make([]byte, len(packet))) // Копия, чтобы избежать гонки
		copy(results[len(results)-1], packet)
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
