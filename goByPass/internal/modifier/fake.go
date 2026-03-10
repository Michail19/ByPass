package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
	"fmt"
	"math/rand"
)

// ApplyFake создает поддельный пакет.
//
// TTL должен подбираться как "расстояние до DPI":
//   - слишком малый → fake не достигает DPI, обход не работает
//   - слишком большой → fake достигает сервера, который получает bad seq/checksum
//     и сбрасывает соединение RST
//     Рекомендуемые значения: 4–8 (настраивается в стратегии как FakeTTL).
func (pm *PacketModifier) ApplyFake(packet []byte, pos int, ttl int, mode strategy.FakeMode, fooling uint32) ([][]byte, error) {
	fake := append([]byte{}, packet...)

	ipHdrLen := int(fake[0]&0x0F) * 4
	tcpOffset := ipHdrLen

	switch mode {
	case strategy.FakeBadSum:
		// ВАЖНО: сначала считаем правильный checksum, потом портим — и больше НЕ пересчитываем.
		// Старый код вызывал FixTCPChecksum в конце, что восстанавливало валидный checksum
		// и делало FakeBadSum бесполезным: DPI принимал пакет как настоящий.
		FixTCPChecksum(fake)
		fake[tcpOffset+16] ^= 0xFF
		fake[tcpOffset+17] ^= 0xFF
		// Только IP checksum (TTL изменится ниже, IP checksum нужно обновить)
		setIPTTL(fake, ttl)
		recalculateIPChecksum(fake)
		// TCP checksum НЕ пересчитываем — он намеренно испорчен
		return [][]byte{fake}, nil

	case strategy.FakeBadSeq:
		delta := uint32(rand.Int31n(1000000) + 1)
		modifyTCPSeq(fake, delta)

	case strategy.FakeDataNoAck:
		clearTCPACK(fake)

	case strategy.FakeMD5Sig:
		var err error
		fake, err = addTCPOptionMD5(fake)
		if err != nil {
			return nil, err
		}
	}

	// Для всех режимов кроме FakeBadSum: устанавливаем TTL и пересчитываем checksums
	setIPTTL(fake, ttl)
	recalculateIPChecksum(fake)
	FixTCPChecksum(fake)

	return [][]byte{fake}, nil
}

// modifyTCPWindow изменяет window size (для ACK)
func modifyTCPWindow(packet []byte, window uint16) {
	if len(packet) < 40 || packet[9] != 6 {
		return // или error
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	if len(packet) < tcpHeaderOffset+20 {
		return
	}

	// Window size в байтах 14-15 TCP заголовка
	binary.BigEndian.PutUint16(packet[tcpHeaderOffset+14:], window)
}

// addTCPOptionMD5 добавляет опцию MD5 Signature в TCP заголовок и возвращает новый пакет
func addTCPOptionMD5(packet []byte) ([]byte, error) {
	if len(packet) < 40 {
		return nil, fmt.Errorf("packet too short")
	}

	// Проверяем, что это TCP
	if packet[9] != 6 {
		return nil, fmt.Errorf("not TCP packet")
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen

	if len(packet) < tcpHeaderOffset+20 {
		return nil, fmt.Errorf("packet too short for TCP header")
	}

	// Определяем длину TCP заголовка
	tcpHeaderLenWords := int(packet[tcpHeaderOffset+12] >> 4)
	tcpHeaderLen := tcpHeaderLenWords * 4

	// Новый TCP заголовок с опцией MD5 (18 байт, но выравниваем на 20 для простоты)
	newTCPHeaderLen := tcpHeaderLen + 20
	if newTCPHeaderLen > 60 {
		return nil, fmt.Errorf("TCP header too long")
	}

	// Новый полный пакет
	newPacketLen := ipHeaderLen + newTCPHeaderLen + (len(packet) - tcpHeaderOffset - tcpHeaderLen)
	newPacket := make([]byte, newPacketLen)

	// Копируем IP заголовок
	copy(newPacket[:ipHeaderLen], packet[:ipHeaderLen])

	// Копируем старый TCP заголовок
	copy(newPacket[ipHeaderLen:ipHeaderLen+tcpHeaderLen], packet[tcpHeaderOffset:tcpHeaderOffset+tcpHeaderLen])

	// Добавляем опцию MD5
	optPos := ipHeaderLen + tcpHeaderLen
	newPacket[optPos] = 19   // kind MD5
	newPacket[optPos+1] = 18 // length
	// 16 байт данных (нулями)

	// Копируем данные после TCP заголовка
	if len(packet) > tcpHeaderOffset+tcpHeaderLen {
		copy(newPacket[ipHeaderLen+newTCPHeaderLen:], packet[tcpHeaderOffset+tcpHeaderLen:])
	}

	// Обновляем длину TCP заголовка
	newTCPHeaderLenWords := newTCPHeaderLen / 4
	newPacket[ipHeaderLen+12] = byte(newTCPHeaderLenWords<<4) | (packet[tcpHeaderOffset+12] & 0x0F)

	// Обновляем totalLen в IP
	newTotalLen := uint16(newPacketLen)
	binary.BigEndian.PutUint16(newPacket[2:4], newTotalLen)

	// Пересчитываем IP checksum
	binary.BigEndian.PutUint16(newPacket[10:12], 0)
	ipChecksum := calculateIPChecksum(newPacket[:ipHeaderLen])
	binary.BigEndian.PutUint16(newPacket[10:12], ipChecksum)

	// Пересчитываем TCP checksum (позже в вызывающем коде)

	return newPacket, nil
}

// modifyTCPSeq изменяет sequence number
func modifyTCPSeq(packet []byte, delta uint32) {
	if len(packet) < 40 || packet[9] != 6 {
		return // или error
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	if len(packet) < tcpHeaderOffset+20 {
		return
	}

	// Sequence number находится в байтах 4-7 TCP заголовка
	seq := binary.BigEndian.Uint32(packet[tcpHeaderOffset+4:])
	seq += delta
	binary.BigEndian.PutUint32(packet[tcpHeaderOffset+4:], seq)
}

// clearTCPACK сбрасывает флаг ACK
func clearTCPACK(packet []byte) {
	if len(packet) < 40 || packet[9] != 6 {
		return // или error
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	if len(packet) < tcpHeaderOffset+20 {
		return
	}

	// Флаги находятся в байте 13 TCP заголовка
	// Сбрасываем бит ACK (0x10)
	packet[tcpHeaderOffset+13] &^= 0x10
}
