package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
	"fmt"
)

// ApplyFake создаёт поддельный пакет на основе оригинала.
//
// fakePayload — если не nil, заменяет TCP payload в fake-пакете
// (используется для FakeTLSFile/FakeTLSMod режимов).
//
// Fooling-маска определяет, как fake-пакет будет "невидим" для сервера:
//   - FoolingTS     : обнулить TCP Timestamp → сервер дропнет тихо
//   - FoolingMD5Sig : добавить TCP MD5 опцию → unsupported, дроп
//   - FoolingBadSum : испортить TCP checksum → сервер дропнет, DPI принимает
//   - FoolingBadSeq : seq += BadSeqIncrement → вне TCP-окна у сервера
//   - FoolingDataNoAck : убрать флаг ACK
//
// Для FoolingBadSum: TCP checksum намеренно испорчен и НЕ пересчитывается после.
func (pm *PacketModifier) ApplyFake(
	packet []byte,
	ttl int,
	fooling uint32,
	badSeqIncrement int64,
	fakePayload []byte,
) ([][]byte, error) {

	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return nil, fmt.Errorf("invalid packet")
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpOffset := ipHdrLen
	tcpHdrLen := int(packet[tcpOffset+12]>>4) * 4
	payloadOffset := tcpOffset + tcpHdrLen

	var fake []byte

	if fakePayload != nil {
		// Заменяем TCP payload на fakePayload (например, другой TLS ClientHello)
		newLen := payloadOffset + len(fakePayload)
		fake = make([]byte, newLen)
		copy(fake, packet[:payloadOffset])
		copy(fake[payloadOffset:], fakePayload)
		binary.BigEndian.PutUint16(fake[2:4], uint16(newLen))
	} else {
		fake = make([]byte, len(packet))
		copy(fake, packet)
	}

	// FoolingBadSum: специальный путь — портим checksum и выходим сразу.
	// FixTCPChecksum в конце НЕ вызываем — это сломало бы весь смысл.
	if fooling&strategy.FoolingBadSum != 0 {
		setIPTTL(fake, ttl)
		recalculateIPChecksum(fake)
		FixTCPChecksum(fake) // сначала считаем правильный
		fake[tcpOffset+16] ^= 0xFF
		fake[tcpOffset+17] ^= 0xFF
		// IP checksum уже правильный, TCP умышленно испорчен
		return [][]byte{fake}, nil
	}

	// Остальные режимы
	if fooling&strategy.FoolingBadSeq != 0 {
		if badSeqIncrement == 0 {
			badSeqIncrement = 2 // минимальный безопасный дефолт
		}
		seq := binary.BigEndian.Uint32(fake[tcpOffset+4:])
		seq += uint32(badSeqIncrement)
		binary.BigEndian.PutUint32(fake[tcpOffset+4:], seq)
	}

	if fooling&strategy.FoolingDataNoAck != 0 {
		fake[tcpOffset+13] &^= 0x10 // clear ACK
	}

	if fooling&strategy.FoolingTS != 0 {
		zeroTCPTimestamp(fake, ipHdrLen)
	}

	if fooling&strategy.FoolingMD5Sig != 0 {
		var err error
		fake, err = addTCPOptionMD5(fake)
		if err != nil {
			return nil, err
		}
	}

	setIPTTL(fake, ttl)
	recalculateIPChecksum(fake)
	FixTCPChecksum(fake)

	return [][]byte{fake}, nil
}

// zeroTCPTimestamp обнуляет значение TCP Timestamp опции (kind=8).
// Сервер получает пакет с timestamp=0, который не совпадает с его окном →
// пакет отбрасывается тихо (RFC 7323, §5.3).
func zeroTCPTimestamp(packet []byte, ipHdrLen int) {
	tcpOffset := ipHdrLen
	tcpHdrLen := int(packet[tcpOffset+12]>>4) * 4
	optStart := tcpOffset + 20
	optEnd := tcpOffset + tcpHdrLen

	if optEnd > len(packet) {
		optEnd = len(packet)
	}

	pos := optStart
	for pos < optEnd {
		kind := packet[pos]
		switch kind {
		case 0: // End of Options
			return
		case 1: // NOP
			pos++
		case 8: // Timestamp (kind=8, len=10: val[4] + ecr[4])
			if pos+10 <= optEnd {
				// val: bytes [pos+2..pos+5] → ставим 0
				packet[pos+2] = 0
				packet[pos+3] = 0
				packet[pos+4] = 0
				packet[pos+5] = 0
				// ecr: bytes [pos+6..pos+9] → тоже 0 (опционально)
				packet[pos+6] = 0
				packet[pos+7] = 0
				packet[pos+8] = 0
				packet[pos+9] = 0
			}
			return
		default:
			if pos+1 >= optEnd {
				return
			}
			length := int(packet[pos+1])
			if length < 2 {
				return
			}
			pos += length
		}
	}
}

// modifyTCPSeq изменяет sequence number (legacy, используется в disorder.go)
func modifyTCPSeq(packet []byte, delta uint32) {
	if len(packet) < 40 || packet[9] != 6 {
		return
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	if len(packet) < tcpHeaderOffset+20 {
		return
	}
	seq := binary.BigEndian.Uint32(packet[tcpHeaderOffset+4:])
	seq += delta
	binary.BigEndian.PutUint32(packet[tcpHeaderOffset+4:], seq)
}

// clearTCPACK сбрасывает флаг ACK
func clearTCPACK(packet []byte) {
	if len(packet) < 40 || packet[9] != 6 {
		return
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	packet[ipHeaderLen+13] &^= 0x10
}

// addTCPOptionMD5 добавляет опцию MD5 Signature (kind=19, len=18)
func addTCPOptionMD5(packet []byte) ([]byte, error) {
	if len(packet) < 40 {
		return nil, fmt.Errorf("packet too short")
	}
	if packet[9] != 6 {
		return nil, fmt.Errorf("not TCP")
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderLenWords := int(packet[ipHeaderLen+12] >> 4)
	tcpHeaderLen := tcpHeaderLenWords * 4

	// MD5 option: kind(1) + len(1) + md5(16) = 18 байт, выравниваем до 20 (NOP×2)
	addLen := 20
	newTCPHeaderLen := tcpHeaderLen + addLen
	if newTCPHeaderLen > 60 {
		return nil, fmt.Errorf("TCP header overflow")
	}

	dataOffset := ipHeaderLen + tcpHeaderLen
	newPacketLen := ipHeaderLen + newTCPHeaderLen + (len(packet) - dataOffset)
	newPkt := make([]byte, newPacketLen)

	copy(newPkt[:ipHeaderLen], packet[:ipHeaderLen])
	copy(newPkt[ipHeaderLen:ipHeaderLen+tcpHeaderLen], packet[ipHeaderLen:ipHeaderLen+tcpHeaderLen])

	optPos := ipHeaderLen + tcpHeaderLen
	newPkt[optPos] = 19   // kind: MD5
	newPkt[optPos+1] = 18 // length
	// 16 байт MD5 (нули достаточно — сервер дропнет из-за неверного значения)

	if len(packet) > dataOffset {
		copy(newPkt[ipHeaderLen+newTCPHeaderLen:], packet[dataOffset:])
	}

	// Обновить data offset в TCP заголовке
	newPkt[ipHeaderLen+12] = byte(newTCPHeaderLen/4<<4) | (packet[ipHeaderLen+12] & 0x0F)

	// Обновить Total Length в IP
	binary.BigEndian.PutUint16(newPkt[2:4], uint16(newPacketLen))

	return newPkt, nil
}

// modifyTCPWindow изменяет window size
func modifyTCPWindow(packet []byte, window uint16) {
	if len(packet) < 40 || packet[9] != 6 {
		return
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	binary.BigEndian.PutUint16(packet[ipHeaderLen+14:], window)
}
