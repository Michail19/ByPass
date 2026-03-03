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
		// Добавляем TCP опцию MD5 Signature
		addTCPOptionMD5(fakePacket)

	case strategy.FakeBadSeq:
		// Изменяем sequence number
		modifyTCPSeq(fakePacket, 12345)

	case strategy.FakeDataNoAck:
		// Устанавливаем флаг ACK в 0
		clearTCPACK(fakePacket)

	default:
		// По умолчанию просто забиваем нулями часть пакета
		for i := fakePos; i < len(fakePacket); i++ {
			fakePacket[i] = 0
		}
	}

	// Устанавливаем низкий TTL для фейка
	setIPTTL(fakePacket, fakeTTL)

	return [][]byte{fakePacket, packet}, nil
}

// addTCPOptionMD5 добавляет опцию MD5 Signature в TCP заголовок
func addTCPOptionMD5(packet []byte) {
	if len(packet) < 40 { // IP(20) + TCP(20) минимум
		return
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	tcpHeaderOffset := int(ipHeaderLen)

	if len(packet) < tcpHeaderOffset+20 {
		return
	}

	// Опция MD5 Signature (kind=19, len=18)
	// Упрощенно - в реальности нужно правильно вставлять в опции
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
