package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
)

// ApplyDisorder применяет нарушение порядка в стиле zapret.
func (pm *PacketModifier) ApplyDisorder(
	packet []byte,
	disorderPos []int,
	ttl int,
	mode strategy.DisorderMode,
	fooling uint32,
	badSeqIncrement int64,
) ([][]byte, error) {
	if len(disorderPos) == 0 {
		return nil, nil
	}

	ipHdrLen, tcpHdrLen, payloadOffset, err := parseIPv4TCP(packet)
	if err != nil {
		return nil, err
	}

	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return nil, nil
	}

	var validPos []int
	for _, pos := range disorderPos {
		if pos > 0 && pos < payloadLen {
			validPos = append(validPos, pos)
		}
	}
	if len(validPos) == 0 {
		return nil, nil
	}
	sortInts(validPos)
	validPos = dedupInts(validPos)

	realSegs, err := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, validPos)
	if err != nil {
		return nil, err
	}
	reversed := reversePackets(realSegs)

	originalSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
	var results [][]byte

	switch mode {
	case strategy.DisorderOutOfBand:
		oobPkt := make([]byte, len(packet))
		copy(oobPkt, packet)
		binary.BigEndian.PutUint32(oobPkt[ipHdrLen+4:], originalSeq-512)
		_ = setIPTTL(oobPkt, ttl)
		if err := fixPacketChecksums(oobPkt); err != nil {
			return nil, err
		}
		results = append(results, oobPkt)
		results = append(results, reversed...)

	case strategy.DisorderFakedDisorder:
		fakePkts, err := pm.ApplyFake(packet, ttl, fooling, badSeqIncrement, nil)
		if err != nil {
			return nil, err
		}
		results = append(results, fakePkts...)
		results = append(results, reversed...)

	default:
		segs, err := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, validPos)
		if err != nil {
			return nil, err
		}

		// Настоящий multidisorder: реальные сегменты в обратном порядке.
		for i := len(segs) - 1; i >= 0; i-- {
			results = append(results, segs[i])
		}
	}

	return results, nil
}

func reversePackets(pkts [][]byte) [][]byte {
	out := make([][]byte, len(pkts))
	for i := range pkts {
		out[i] = pkts[len(pkts)-1-i]
	}
	return out
}

// setIPTTL устанавливает TTL в IP-заголовке и пересчитывает IP checksum.
//
// Если ttl <= 0 — используем безопасный default=6 (#BugTTL0):
// ttl=0 → packet[8]=0 → первый же маршрутизатор дропает пакет с ICMP Time Exceeded
// ещё до того как он достигает DPI → fake/decoy не имеет никакого эффекта.
// Это касается всех стратегий с fake_ttl=0 или disorder_ttl=0 в JSON.
func setIPTTL(packet []byte, ttl int) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	if ttl <= 0 {
		ttl = 6 // zapret default: достаточно чтобы дойти до DPI, умереть до сервера
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

// dedupInts удаляет дубликаты из уже отсортированного среза без аллокации (#10).
// Работает in-place: возвращает подрез исходного слайса.
func dedupInts(a []int) []int {
	if len(a) <= 1 {
		return a
	}
	w := 1
	for i := 1; i < len(a); i++ {
		if a[i] != a[i-1] {
			a[w] = a[i]
			w++
		}
	}
	return a[:w]
}
