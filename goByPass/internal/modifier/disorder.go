package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
)

// ApplyDisorder применяет нарушение порядка в стиле zapret.
//
// НЕ меняет порядок TCP сегментов (→ missing packets → duplicate ACK → slow start reset).
// Вместо этого: decoy с низким TTL + реальные сегменты в прямом порядке.
//
// DisorderOutOfBand:  OOB decoy (bad seq + low TTL), затем все сегменты прямо
// DisorderTTLZero:    decoy = первый сегмент с TTL=disorder_ttl, затем все сегменты
// DisorderFakedDisorder: fake-пакет перед сегментами
// DisorderMulti:      disorder в нескольких позициях (multidisorder)
func (pm *PacketModifier) ApplyDisorder(
	packet []byte,
	disorderPos []int,
	ttl int,
	mode strategy.DisorderMode,
	fooling uint32,
	badSeqIncrement int64,
) ([][]byte, error) {

	if len(disorderPos) == 0 || ttl <= 0 {
		return nil, nil
	}
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return nil, nil
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return nil, nil
	}

	seen := map[int]bool{}
	var validPos []int
	for _, pos := range disorderPos {
		if pos > 0 && pos < payloadLen && !seen[pos] {
			validPos = append(validPos, pos)
			seen[pos] = true
		}
	}
	if len(validPos) == 0 {
		return nil, nil
	}
	sortInts(validPos)

	originalSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
	var results [][]byte

	switch mode {
	case strategy.DisorderOutOfBand:
		// OOB: пакет с заведомо неверным seq + low TTL
		oobPkt := make([]byte, len(packet))
		copy(oobPkt, packet)
		binary.BigEndian.PutUint32(oobPkt[ipHdrLen+4:], 0xFFFFFFFF)
		setIPTTL(oobPkt, ttl)
		recalculateIPChecksum(oobPkt)
		FixTCPChecksum(oobPkt)
		results = append(results, oobPkt)

	case strategy.DisorderFakedDisorder:
		// Fake-пакет перед реальными сегментами
		fakePkts, _ := pm.ApplyFake(packet, ttl, fooling, badSeqIncrement, nil)
		results = append(results, fakePkts...)

	default:
		// TTLZero / MultiDisorder / default:
		// Decoy = первый сегмент с TTL=disorder_ttl
		// DPI видит начало ClientHello, думает что поток начался,
		// пакет не доходит до сервера (TTL истекает).
		firstSegEnd := payloadOffset + validPos[0]
		decoy := make([]byte, firstSegEnd)
		copy(decoy, packet[:payloadOffset])
		binary.BigEndian.PutUint16(decoy[2:4], uint16(firstSegEnd))
		binary.BigEndian.PutUint32(decoy[ipHdrLen+4:], originalSeq)
		copy(decoy[payloadOffset:], packet[payloadOffset:firstSegEnd])
		decoy[6] &^= 0x40
		setIPTTL(decoy, ttl)
		recalculateIPChecksum(decoy)
		FixTCPChecksum(decoy)
		results = append(results, decoy)
	}

	// Реальные сегменты в прямом порядке
	realSegs := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, validPos)
	results = append(results, realSegs...)

	return results, nil
}

// setIPTTL устанавливает TTL в IP-заголовке и пересчитывает IP checksum
func setIPTTL(packet []byte, ttl int) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	packet[8] = byte(ttl)
	recalculateIPChecksum(packet)
	return nil
}

// recalculateIPChecksum пересчитывает IP checksum с учётом IHL (IP options)
func recalculateIPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl {
		return
	}
	packet[10] = 0
	packet[11] = 0
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
}

// sortInts — inline insertion sort для малых срезов (обычно 2–5 элементов)
func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
