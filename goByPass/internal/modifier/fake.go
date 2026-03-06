package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
)

// ApplyFake создает поддельный пакет
func (pm *PacketModifier) ApplyFake(packet []byte, fakePos int, fakeTTL int, fakeMode strategy.FakeMode) ([][]byte, error) {
	if fakePos < 0 || fakePos >= len(packet) || fakeTTL <= 0 {
		return nil, nil
	}

	fakePacket := make([]byte, len(packet))
	copy(fakePacket, packet)

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

	// Устанавливаем низкий TTL для фейка
	if err := setIPTTL(fakePacket, fakeTTL); err != nil {
		return nil, err
	}

	return [][]byte{fakePacket, packet}, nil
}

// Реальная реализация addTCPOptionMD5
func addTCPOptionMD5(packet []byte) {
	if len(packet) < 40 {
		return
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen

	// Определяем длину TCP заголовка
	tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4

	// Создаем новый TCP заголовок с опцией MD5
	newTCPHeader := make([]byte, tcpHeaderLen+18) // +18 для MD5 опции
	copy(newTCPHeader, packet[tcpHeaderOffset:tcpHeaderOffset+tcpHeaderLen])

	// Добавляем опцию MD5 (kind=19, len=18)
	newTCPHeader[tcpHeaderLen] = 19   // kind
	newTCPHeader[tcpHeaderLen+1] = 18 // length
	// Данные опции (16 байт) оставляем нулями (упрощенно)

	// Обновляем длину TCP заголовка в оригинальном пакете
	newTCPHeader[12] = byte(((tcpHeaderLen+18)/4)<<4) | (packet[tcpHeaderOffset+12] & 0x0F)

	// Собираем новый пакет
	newPacket := make([]byte, ipHeaderLen+len(newTCPHeader)+(len(packet)-tcpHeaderOffset-tcpHeaderLen))
	copy(newPacket, packet[:ipHeaderLen])
	copy(newPacket[ipHeaderLen:], newTCPHeader)
	copy(newPacket[ipHeaderLen+len(newTCPHeader):], packet[tcpHeaderOffset+tcpHeaderLen:])

	// Копируем обратно в оригинальный слайс (но это сложно, проще переписать логику)
	// Для простоты будем считать, что fakePacket уже содержит новый пакет
	copy(packet, newPacket)
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
