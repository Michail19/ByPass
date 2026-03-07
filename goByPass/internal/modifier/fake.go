package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
	"fmt"
)

// ApplyFake создает поддельный пакет
func (pm *PacketModifier) ApplyFake(packet []byte, fakePos int, fakeTTL int, fakeMode strategy.FakeMode) ([][]byte, error) {
	if fakePos < 0 || fakePos >= len(packet) || fakeTTL <= 0 {
		return nil, nil
	}

	fakePacket := make([]byte, len(packet))
	copy(fakePacket, packet)

	// Проверяем, является ли пакет ACK (flags ACK, no data)
	isACK := false
	if len(packet) >= 40 && packet[9] == 6 { // TCP
		ipHeaderLen := int(packet[0]&0x0F) * 4
		tcpHeaderOffset := ipHeaderLen
		tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4
		dataLen := len(packet) - tcpHeaderOffset - tcpHeaderLen
		flags := packet[tcpHeaderOffset+13]
		if (flags&0x10) != 0 && dataLen == 0 {
			isACK = true
		}
	}

	switch fakeMode {
	case strategy.FakeMD5Sig:
		newFake, err := addTCPOptionMD5(fakePacket)
		if err != nil {
			// log или пропустить
			break
		}
		fakePacket = newFake
		FixTCPChecksum(fakePacket)

	case strategy.FakeBadSeq:
		// Изменяем sequence number
		modifyTCPSeq(fakePacket, 12345)
		// Пересчитываем checksum после изменения
		FixTCPChecksum(fakePacket)

	case strategy.FakeDataNoAck:
		// Устанавливаем флаг ACK в 0
		clearTCPACK(fakePacket)
		FixTCPChecksum(fakePacket)

	default:
		// По умолчанию просто забиваем нулями часть пакета
		for i := fakePos; i < len(fakePacket); i++ {
			fakePacket[i] = 0
		}
		FixTCPChecksum(fakePacket)
	}

	// Для ACK можно добавить специфическую модификацию (пример: занижаем window size)
	if isACK {
		modifyTCPWindow(fakePacket, 42) // Пример изменения window
		FixTCPChecksum(fakePacket)
	}

	// Устанавливаем низкий TTL для фейка
	if err := setIPTTL(fakePacket, fakeTTL); err != nil {
		return nil, err
	}

	return [][]byte{fakePacket, packet}, nil
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
