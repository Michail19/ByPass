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
// DisorderOutOfBand:      OOB decoy (bad seq + low TTL), затем все сегменты прямо
// DisorderTTLZero:        decoy = первый сегмент с TTL=disorder_ttl, затем все сегменты
// DisorderFakedDisorder:  fake-пакет перед сегментами
// DisorderMulti:          disorder в нескольких позициях (multidisorder)
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

	// Dedup без map-аллокации (#10): sort + linear pass
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

	originalSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
	var results [][]byte

	switch mode {
	case strategy.DisorderOutOfBand:
		// OOB: пакет с заведомо неверным seq + low TTL.
		// seq = originalSeq - 512: гарантированно вне TCP-окна сервера.
		// Было -1: при начальном окне 64–256 KB seq-1 всё ещё внутри окна →
		// сервер отвечал Duplicate ACK → out-of-order → slow start reset.
		// Zapret использует смещение ~500–700 байт (ovl_len).
		// -512 достаточно велико чтобы выйти за окно, но не является
		// очевидным паттерном (0xFFFFFFFF) детектируемым DPI (#3).
		oobPkt := make([]byte, len(packet))
		copy(oobPkt, packet)
		binary.BigEndian.PutUint32(oobPkt[ipHdrLen+4:], originalSeq-512)
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
		// DF: сохраняем из оригинала (#6) — decoy скопирован из packet[:payloadOffset],
		// packet[6] уже содержит оригинальные Flags+FragOffset.
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
