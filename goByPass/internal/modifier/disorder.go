package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
)

// ApplyDisorder применяет нарушение порядка (reverse order segments + optional low TTL fake prefix)
func (pm *PacketModifier) ApplyDisorder(packet []byte, disorderPos []int, ttl int, mode strategy.DisorderMode) ([][]byte, error) {
	if len(disorderPos) == 0 || ttl <= 0 {
		return nil, nil
	}

	// Проверяем TCP/IPv4
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return nil, nil
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4
	payloadOffset := tcpHeaderOffset + tcpHeaderLen
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return nil, nil // No payload to disorder
	}

	var results [][]byte

	// Split payload into segments at positions
	segments := [][]byte{}
	prevPos := 0
	for _, pos := range disorderPos {
		if pos <= prevPos || pos >= payloadLen {
			continue
		}
		segments = append(segments, packet[payloadOffset+prevPos:payloadOffset+pos])
		prevPos = pos
	}
	segments = append(segments, packet[payloadOffset+prevPos:]) // Last segment

	strat := pm.strategyManager.GetActive()

	if strat != nil && strat.DisorderMode == strategy.DisorderOutOfBand {
		oobPkt := make([]byte, len(packet))
		copy(oobPkt, packet)
		// Bad seq + low TTL
		modifyTCPSeq(oobPkt, 0xFFFFFFFF)
		setIPTTL(oobPkt, ttl)
		recalculateIPChecksum(oobPkt)
		FixTCPChecksum(oobPkt)
		results = append(results, oobPkt) // OOB первый
	}

	// Reverse order for disorder (like GoodbyeDPI reverse-frag)
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		segLen := len(seg)

		// Create new TCP segment packet
		newPkt := make([]byte, ipHeaderLen+tcpHeaderLen+segLen)
		copy(newPkt, packet[:payloadOffset]) // Copy headers

		// Update totalLen in IP
		binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))

		// Update seq (increment by previous segments total len)
		seq := binary.BigEndian.Uint32(newPkt[tcpHeaderOffset+4:])
		seq += uint32(payloadOffset + (payloadLen - segLen - prevPos)) // Adjust for position
		binary.BigEndian.PutUint32(newPkt[tcpHeaderOffset+4:], seq)

		// Copy segment data
		copy(newPkt[payloadOffset:], seg)

		// Optional low TTL for first "fake" segment
		if i == len(segments)-1 { // First in reverse = last original
			err := setIPTTL(newPkt, ttl)
			if err != nil {
				return nil, err
			} // Low TTL for disorder fake
		}

		// Recalculate checksums only once
		recalculateIPChecksum(newPkt)
		err := FixTCPChecksum(newPkt)
		if err != nil {
			return nil, err
		}

		results = append(results, newPkt)
	}

	if mode == strategy.DisorderFakedDisorder {
		// fakeddisorder: fake first + disorder segments
		fakePkts, _ := pm.ApplyFake(packet, 0, ttl, strategy.FakeBadSeq, 0)
		if len(fakePkts) > 0 {
			results = append(results, fakePkts[0])
		}
	}

	return results, nil
}

// setIPTTL + recalculate in one (optimized)
func setIPTTL(packet []byte, ttl int) error {
	if len(packet) < 20 || (packet[0]>>4 != 4) {
		return nil
	}

	packet[8] = byte(ttl)

	// Пересчитываем контрольную сумму
	recalculateIPChecksum(packet)

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
