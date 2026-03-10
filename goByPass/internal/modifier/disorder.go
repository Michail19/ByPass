package modifier

import (
	"ByPass/internal/strategy"
	"encoding/binary"
)

// ApplyDisorder применяет нарушение порядка в стиле zapret:
//
//	НЕ меняет порядок TCP-сегментов — это вызывает missing packets, duplicate ACK,
//	retransmission и slow start reset, что делает YouTube/Discord медленными.
//
// Вместо этого используется подход zapret/byedpi:
//  1. "Decoy" пакет с данными первого сегмента и TTL=disorder_ttl отправляется первым.
//     TTL выбирается так, чтобы пакет дошёл до DPI, но не достиг сервера.
//     DPI видит "нормальный" начальный сегмент и не блокирует соединение.
//  2. Остальные сегменты отправляются в нормальном (возрастающем) порядке.
//     Сервер получает правильную последовательность и собирает TCP stream.
//
// Для DisorderOutOfBand: вместо decoy отправляется пакет с bad seq + low TTL,
// который DPI дезориентирует, но сервер отбрасывает как out-of-window.
func (pm *PacketModifier) ApplyDisorder(packet []byte, disorderPos []int, ttl int, mode strategy.DisorderMode) ([][]byte, error) {
	if len(disorderPos) == 0 || ttl <= 0 {
		return nil, nil
	}

	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return nil, nil
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4
	payloadOffset := tcpHeaderOffset + tcpHeaderLen
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return nil, nil
	}

	// Собираем позиции разбиения (только валидные, без дублей)
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

	// Сортируем позиции — иначе сегменты будут неправильными (Fix 5 из split.go тоже)
	sortInts(validPos)

	// Разбиваем payload на сегменты
	var segments [][]byte
	prevPos := 0
	for _, pos := range validPos {
		segments = append(segments, packet[payloadOffset+prevPos:payloadOffset+pos])
		prevPos = pos
	}
	segments = append(segments, packet[payloadOffset+prevPos:])

	originalSeq := binary.BigEndian.Uint32(packet[tcpHeaderOffset+4:])
	var results [][]byte

	switch mode {
	case strategy.DisorderOutOfBand:
		// OOB decoy: bad seq + low TTL — DPI дезориентирован, сервер отбросит как out-of-window
		oobPkt := make([]byte, len(packet))
		copy(oobPkt, packet)
		modifyTCPSeq(oobPkt, 0xFFFFFFFF) // заведомо неверный seq
		setIPTTL(oobPkt, ttl)
		recalculateIPChecksum(oobPkt)
		FixTCPChecksum(oobPkt)
		results = append(results, oobPkt)

	default:
		// TTLZero / ReverseFrag / прочие:
		// Decoy = первый сегмент с низким TTL.
		// DPI видит начало ClientHello и думает, что поток начался.
		// Пакет не доходит до сервера (TTL истекает на пути).
		firstSeg := segments[0]
		decoy := make([]byte, ipHeaderLen+tcpHeaderLen+len(firstSeg))
		copy(decoy, packet[:payloadOffset])
		binary.BigEndian.PutUint16(decoy[2:4], uint16(len(decoy)))
		binary.BigEndian.PutUint32(decoy[tcpHeaderOffset+4:], originalSeq)
		copy(decoy[payloadOffset:], firstSeg)
		decoy[6] &= ^byte(0x40) // clear DF
		setIPTTL(decoy, ttl)
		recalculateIPChecksum(decoy)
		FixTCPChecksum(decoy)
		results = append(results, decoy)
	}

	// Реальные сегменты в ПРЯМОМ порядке (seq возрастает)
	// Сервер получает правильную последовательность и собирает stream без retransmit
	seqOffset := uint32(0)
	for _, seg := range segments {
		segLen := len(seg)
		newPkt := make([]byte, ipHeaderLen+tcpHeaderLen+segLen)
		copy(newPkt, packet[:payloadOffset])
		binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
		binary.BigEndian.PutUint32(newPkt[tcpHeaderOffset+4:], originalSeq+seqOffset)
		copy(newPkt[payloadOffset:], seg)
		newPkt[6] &= ^byte(0x40) // clear DF
		recalculateIPChecksum(newPkt)
		FixTCPChecksum(newPkt)
		results = append(results, newPkt)
		seqOffset += uint32(segLen)
	}

	if mode == strategy.DisorderFakedDisorder {
		// fakeddisorder: дополнительный fake перед реальными сегментами
		fakePkts, _ := pm.ApplyFake(packet, 0, ttl, strategy.FakeBadSeq, 0)
		if len(fakePkts) > 0 {
			// Вставляем fake перед реальными сегментами (после OOB/decoy)
			results = append([][]byte{results[0]}, append(fakePkts, results[1:]...)...)
		}
	}

	return results, nil
}

// sortInts сортирует []int по возрастанию без импорта sort (inline insertion sort для малых срезов)
func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
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

// recalculateIPChecksum пересчитывает контрольную сумму IP-заголовка.
// Использует IHL из байта 0 — IP-опции (IHL > 20) увеличивают заголовок до 60 байт.
// При hardcoded 20 checksum будет неверным и пакет дропнет маршрутизатор.
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
