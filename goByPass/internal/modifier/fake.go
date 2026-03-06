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
		// Добавляем TCP опцию MD5 Signature (kind=19, len=18)
		addTCPOptionMD5(fakePacket)
		// После добавления опции нужно пересчитать checksum
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
	if len(packet) < 40 {
		return
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	tcpHeaderOffset := int(ipHeaderLen)

	if len(packet) < tcpHeaderOffset+16 {
		return
	}

	// Window size в байтах 14-15 TCP заголовка
	binary.BigEndian.PutUint16(packet[tcpHeaderOffset+14:], window)
}

// addTCPOptionMD5 добавляет опцию MD5 Signature в TCP заголовок
func addTCPOptionMD5(packet []byte) error {
	if len(packet) < 40 {
		return fmt.Errorf("packet too short")
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen

	if len(packet) < tcpHeaderOffset+20 {
		return fmt.Errorf("packet too short for TCP header")
	}

	// Определяем длину TCP заголовка (в 32-битных словах)
	tcpHeaderLenWords := int(packet[tcpHeaderOffset+12] >> 4)
	tcpHeaderLen := tcpHeaderLenWords * 4

	// Создаем новый TCP заголовок с местом для опции MD5
	newTCPHeaderLen := tcpHeaderLen + 20
	if newTCPHeaderLen > 60 { // Максимальная длина TCP заголовка
		return fmt.Errorf("TCP header too long")
	}

	// Создаем новый полный пакет
	newPacketLen := ipHeaderLen + newTCPHeaderLen + (len(packet) - tcpHeaderOffset - tcpHeaderLen)
	newPacket := make([]byte, newPacketLen)

	// Копируем IP заголовок
	copy(newPacket[:ipHeaderLen], packet[:ipHeaderLen])

	// Копируем старый TCP заголовок
	copy(newPacket[ipHeaderLen:ipHeaderLen+tcpHeaderLen], packet[tcpHeaderOffset:tcpHeaderOffset+tcpHeaderLen])

	// Добавляем опцию MD5 в конец TCP заголовка
	optPos := ipHeaderLen + tcpHeaderLen
	newPacket[optPos] = 19   // kind MD5
	newPacket[optPos+1] = 18 // length
	// Данные опции (16 байт) оставляем нулями

	// Копируем оставшиеся данные (после TCP заголовка)
	if len(packet) > tcpHeaderOffset+tcpHeaderLen {
		copy(newPacket[ipHeaderLen+newTCPHeaderLen:],
			packet[tcpHeaderOffset+tcpHeaderLen:])
	}

	// Обновляем длину TCP заголовка в IP пакете
	newTCPHeaderLenWords := newTCPHeaderLen / 4
	newPacket[ipHeaderLen+12] = byte(newTCPHeaderLenWords<<4) | (packet[tcpHeaderOffset+12] & 0x0F)

	// Обновляем общую длину в IP заголовке
	newTotalLen := uint16(newPacketLen)
	binary.BigEndian.PutUint16(newPacket[2:4], newTotalLen)

	// Пересчитываем IP checksum
	binary.BigEndian.PutUint16(newPacket[10:12], 0)
	ipChecksum := calculateIPChecksum(newPacket[:ipHeaderLen])
	binary.BigEndian.PutUint16(newPacket[10:12], ipChecksum)

	// Заменяем оригинальный пакет
	copy(packet, newPacket)

	return nil
}

// modifyTCPSeq изменяет sequence number
func modifyTCPSeq(packet []byte, delta uint32) {
	if len(packet) < 40 {
		return
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	tcpHeaderOffset := int(ipHeaderLen)

	if len(packet) < tcpHeaderOffset+8 {
		return
	}

	// Sequence number находится в байтах 4-7 TCP заголовка
	seq := binary.BigEndian.Uint32(packet[tcpHeaderOffset+4:])
	seq += delta
	binary.BigEndian.PutUint32(packet[tcpHeaderOffset+4:], seq)
}

// clearTCPACK сбрасывает флаг ACK
func clearTCPACK(packet []byte) {
	if len(packet) < 40 {
		return
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	tcpHeaderOffset := int(ipHeaderLen)

	if len(packet) < tcpHeaderOffset+13 {
		return
	}

	// Флаги находятся в байте 13 TCP заголовка
	// Сбрасываем бит ACK (0x10)
	packet[tcpHeaderOffset+13] &^= 0x10
}
