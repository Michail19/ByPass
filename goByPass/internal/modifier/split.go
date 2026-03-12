package modifier

import (
	"encoding/binary"
	"log"
)

// ApplySplit применяет разбиение пакета на сегменты в указанных позициях.
// Позиции сортируются — неотсортированный список приводит к перекрытию сегментов.
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int, alignSNI bool) ([][]byte, error) {
	if len(splitPos) == 0 {
		return [][]byte{packet}, nil
	}
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return [][]byte{packet}, nil
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return [][]byte{packet}, nil
	}

	// Dedup без map-аллокации (#10): sort + linear pass
	var validPos []int
	for _, pos := range splitPos {
		if pos > 0 && pos < payloadLen {
			validPos = append(validPos, pos)
		}
	}
	if len(validPos) == 0 {
		return [][]byte{packet}, nil
	}
	sortInts(validPos)
	validPos = dedupInts(validPos)

	return buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, validPos), nil
}

// ApplySeqOvl реализует multisplit с sequence overlap (основная техника zapret/general.bat).
//
// Алгоритм:
//  1. Отправить seqovl-пакет: seq = original_seq - ovlLen, данные = pattern[:ovlLen]
//     DPI видит "старые данные" и теряет контекст для реального ClientHello.
//  2. Отправить реальные сегменты в прямом порядке начиная с original_seq.
//
// ovlLen: типичные значения 568, 652, 664, 679, 681 (из bat-файлов zapret).
// pattern: данные из .bin файла (tls_clienthello_*.bin, stun.bin).
//
// Заметка о TCP window (#2): seqovl-пакет идёт с низким TTL (FakeTTL) и не доходит
// до сервера — только до DPI. Сервер никогда не видит пакет с seq < ISN,
// поэтому TCP window на старте соединения не имеет значения.
func (pm *PacketModifier) ApplySeqOvl(
	packet []byte,
	ovlLen int,
	pattern []byte,
	splitPositions []int,
	seqOvlTTL int, // TTL для seqovl-пакета (#SeqOvlTTL): должен умереть до сервера
) ([][]byte, error) {

	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return [][]byte{packet}, nil
	}
	if ovlLen <= 0 || len(pattern) == 0 {
		return [][]byte{packet}, nil
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return [][]byte{packet}, nil
	}

	originalSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])

	ovlLenN := len(pattern)
	if ovlLenN > ovlLen {
		ovlLenN = ovlLen
	}

	ovlData := pattern[:ovlLenN]

	var results [][]byte

	// 1. SeqOvl пакет: seq = original_seq - len(ovlData)
	ovlPkt := make([]byte, ipHdrLen+tcpHdrLen+len(ovlData))
	copy(ovlPkt, packet[:payloadOffset])
	binary.BigEndian.PutUint16(ovlPkt[2:4], uint16(len(ovlPkt)))
	ovlSeq := originalSeq - uint32(ovlLenN)
	ovlData = ovlData[:ovlLenN]
	binary.BigEndian.PutUint32(ovlPkt[ipHdrLen+4:], ovlSeq)
	copy(ovlPkt[payloadOffset:], ovlData)
	// DF: сохраняем из оригинала (#6) — ovlPkt скопирован из packet[:payloadOffset],
	// packet[6] уже содержит оригинальные Flags+FragOffset.
	//
	// SeqOvl TTL: ovl-пакет должен умереть до сервера — иначе TCP стек сервера
	// получает пакет с seq < ISN, который вне TCP-окна → RST или retransmit (#SeqOvlTTL).
	// Используем seqOvlTTL (обычно DisorderTTL или FakeTTL из стратегии, default 6).
	setIPTTL(ovlPkt, seqOvlTTL)
	recalculateIPChecksum(ovlPkt)
	FixTCPChecksum(ovlPkt)
	results = append(results, ovlPkt)

	// 2. Реальные сегменты в прямом порядке
	// Dedup без map-аллокации (#10)
	var validPos []int
	for _, pos := range splitPositions {
		if pos > 0 && pos < payloadLen {
			validPos = append(validPos, pos)
		}
	}
	sortInts(validPos)
	validPos = dedupInts(validPos)

	if len(validPos) == 0 {
		validPos = []int{1}
	}
	realSegs := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, validPos)
	results = append(results, realSegs...)

	log.Printf("DEBUG: SeqOvl: ovl_len=%d, segments=%d", len(ovlData), len(realSegs))
	return results, nil
}

// ApplyFakedSplit реализует fakedsplit:
// отправить fake-пакет с pattern[0] в позиции fakedSplitPos, затем реальный пакет.
//
// --dpi-desync=fake,fakedsplit --dpi-desync-fakedsplit-pattern=0x00
// DPI видит fake с нулевым байтом и не успевает анализировать реальный следом.
func (pm *PacketModifier) ApplyFakedSplit(
	packet []byte,
	splitPos int,
	patternByte byte,
	fooling uint32,
	badSeqIncrement int64,
	fakeTTL int,
	fakeTLSData []byte,
) ([][]byte, error) {

	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return [][]byte{packet}, nil
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return [][]byte{packet}, nil
	}

	var results [][]byte

	// Fake пакет: оригинальный payload с паттерном вместо первого байта
	var fakePktPayload []byte
	if fakeTLSData != nil {
		fakePktPayload = fakeTLSData
	} else {
		fakePktPayload = make([]byte, payloadLen)
		copy(fakePktPayload, packet[payloadOffset:])
		fakePktPayload[0] = patternByte
	}

	fakePkts, err := pm.ApplyFake(packet, fakeTTL, fooling, badSeqIncrement, fakePktPayload)
	if err == nil {
		results = append(results, fakePkts...)
	}

	// Реальные сегменты
	if splitPos > 0 && splitPos < payloadLen {
		segs := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, []int{splitPos})
		results = append(results, segs...)
	} else {
		results = append(results, packet)
	}

	return results, nil
}

// ApplySynData реализует syndata:
// отправить SYN-пакет с данными fake payload перед реальным SYN.
// DPI теряет начало потока и не успевает анализировать реальный handshake.
//
// Замечание (#5): SYN+data отклоняется некоторыми middlebox'ами (Cloudflare, корп. firewall).
// Включать только для провайдеров где это явно работает.
func (pm *PacketModifier) ApplySynData(packet []byte, fakeData []byte) ([][]byte, error) {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return nil, nil
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4

	flags := packet[ipHdrLen+13]
	isSYN := (flags & 0x02) != 0
	isACK := (flags & 0x10) != 0

	if !isSYN || isACK {
		return nil, nil
	}
	if len(fakeData) == 0 {
		return nil, nil
	}

	originalSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
	synDataSeq := originalSeq - uint32(len(fakeData))

	synPkt := make([]byte, ipHdrLen+tcpHdrLen+len(fakeData))
	copy(synPkt, packet[:ipHdrLen+tcpHdrLen])
	binary.BigEndian.PutUint16(synPkt[2:4], uint16(len(synPkt)))
	binary.BigEndian.PutUint32(synPkt[ipHdrLen+4:], synDataSeq)
	// DF: сохраняем из оригинала (#6) — synPkt скопирован из packet[:ipHdrLen+tcpHdrLen],
	// packet[6] уже содержит оригинальные Flags+FragOffset.
	synPkt[ipHdrLen+13] = flags & 0x02 // оставить только SYN
	copy(synPkt[ipHdrLen+tcpHdrLen:], fakeData)
	recalculateIPChecksum(synPkt)
	FixTCPChecksum(synPkt)

	return [][]byte{synPkt, packet}, nil
}

// buildTCPSegments разбивает packet на TCP-сегменты по validPos (уже отсортированным).
// Если validPos пуст — возвращает packet как есть.
// DF flag: копируется из оригинального packet[6] через copy(newPkt, packet[:payloadOffset]) (#6).
func buildTCPSegments(packet []byte, ipHdrLen, tcpHdrLen, payloadOffset int, validPos []int) [][]byte {
	const overlapBytes = 3

	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return [][]byte{packet}
	}

	var chunks [][]byte
	prev := 0
	for _, pos := range validPos {
		chunks = append(chunks, packet[payloadOffset+prev:payloadOffset+pos])
		prev = pos
	}
	chunks = append(chunks, packet[payloadOffset+prev:])

	seq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
	overlap := 0
	if isClientHelloPacket(packet, payloadOffset, payloadLen) {
		overlap = overlapBytes
	}
	var results [][]byte
	for i, seg := range chunks {
		extra := 0
		if i > 0 && overlap > 0 {
			ov := overlap
			if ov > len(chunks[i-1]) {
				ov = len(chunks[i-1])
			}
			extra = ov
		}

		newPkt := make([]byte, payloadOffset+len(seg)+extra)

		copy(newPkt, packet[:payloadOffset])

		flags := packet[ipHdrLen+13]

		if i != len(chunks)-1 {
			flags &= ^byte(0x01) // FIN
			flags &= ^byte(0x08) // PSH
		}

		newPkt[ipHdrLen+13] = flags // копирует packet[6] включая DF бит

		binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
		binary.BigEndian.PutUint32(newPkt[ipHdrLen+4:], seq)
		if i > 0 && overlap > 0 {
			prev := chunks[i-1]

			ov := overlap
			if ov > len(prev) {
				ov = len(prev)
			}

			overlapData := prev[len(prev)-ov:]

			copy(newPkt[payloadOffset:], overlapData)
			copy(newPkt[payloadOffset+ov:], seg)
		} else {
			copy(newPkt[payloadOffset:], seg)
		}
		// Не трогаем newPkt[6] — DF уже скопирован из оригинала (#6)
		recalculateIPChecksum(newPkt)
		FixTCPChecksum(newPkt)
		results = append(results, newPkt)
		advance := len(seg)

		if i > 0 && overlap > 0 {
			ov := overlap
			if ov > len(chunks[i-1]) {
				ov = len(chunks[i-1])
			}

			if advance > ov {
				advance -= ov
			} else {
				advance = 0
			}
		}

		seq += uint32(advance)
	}
	return results
}

// SplitAtPosition разбивает пакет в указанной позиции
func SplitAtPosition(packet []byte, pos int) [][]byte {
	if pos <= 0 || pos >= len(packet) {
		return [][]byte{packet}
	}
	return [][]byte{packet[:pos], packet[pos:]}
}
