package modifier

import (
	"ByPass/internal/cache"
	"ByPass/internal/conntrack"
	"ByPass/internal/protocol"
	"ByPass/internal/strategy"
	"encoding/binary"
	"fmt"
)

// PacketModifier реализует модификацию пакетов
type PacketModifier struct {
	strategyManager *strategy.Manager
	ipCache         *cache.IPCache
	stats           ModifierStats
}

// ModifierStats статистика модификатора
type ModifierStats struct {
	PacketsProcessed uint64
	PacketsModified  uint64
	SplitCount       uint64
	DisorderCount    uint64
	FakeCount        uint64
	Errors           uint64
}

// ModifyResult содержит результат модификации
type ModifyResult struct {
	StrategyID      int      // ID использованной стратегии
	ModifiedPackets [][]byte // модифицированные версии пакета
	SendOriginal    bool     // нужно ли отправлять оригинал
	Delay           int      // задержка перед отправкой (ms)
}

// NewPacketModifier создает новый модификатор
func NewPacketModifier(sm *strategy.Manager, ic *cache.IPCache) *PacketModifier {
	return &PacketModifier{
		strategyManager: sm,
		ipCache:         ic,
		stats:           ModifierStats{},
	}
}

// ModifyPacket главная функция модификации пакета
func (pm *PacketModifier) ModifyPacket(packet []byte, flow *conntrack.Flow) (*ModifyResult, error) {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	pm.stats.PacketsProcessed++

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrOffset := ipHdrLen
	tcpHdrLen := int(packet[tcpHdrOffset+12]>>4) * 4
	payloadOffset := tcpHdrOffset + tcpHdrLen
	payloadLen := len(packet) - payloadOffset

	if payloadLen <= 0 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	dstIP := flow.GetDstIP()
	strat := pm.strategyManager.SelectStrategy(dstIP, flow.Hostname, int(flow.GetDstPort()), "tcp")
	if strat == nil || strat.ID == 1 { // passthrough
		return &ModifyResult{SendOriginal: true}, nil
	}

	var packets [][]byte

	isClientHello := payloadLen > 5 &&
		packet[payloadOffset] == 0x16 &&
		packet[payloadOffset+1] == 0x03 &&
		packet[payloadOffset+5] == 0x01 // Handshake + ClientHello

	// 1. Fake + repeats (zapret fake + --dpi-desync-repeats)
	if strat.FakeMode != strategy.FakeNone {
		fakeRepeats := strat.Repeats
		if fakeRepeats <= 0 {
			fakeRepeats = 1 // always send at least one fake if FakeMode is set
		}
		for rep := 0; rep < fakeRepeats; rep++ {
			fakePkts, err := pm.ApplyFake(packet, strat.FakePos, strat.FakeTTL, strat.FakeMode, strat.Fooling)

			if err == nil && len(fakePkts) > 0 {
				packets = append(packets, fakePkts...)
				pm.stats.FakeCount += uint64(len(fakePkts))
			}
		}
	}

	// 2. Disorder / fakeddisorder
	if strat.DisorderMode != strategy.DisorderNone {
		disorderPkts, err := pm.ApplyDisorder(packet, strat.DisorderPos, strat.DisorderTTL, strat.DisorderMode)

		if err == nil {
			packets = append(packets, disorderPkts...)
			pm.stats.DisorderCount += uint64(len(disorderPkts))
		}
	}

	// 3. Split / multisplit
	if strat.SplitMode != strategy.SplitNone && isClientHello {
		splitPkts, err := pm.ApplySplit(packet, strat.SplitPositions, strat.SplitSNIOffset)

		if err == nil {
			packets = append(packets, splitPkts...)
			pm.stats.SplitCount += uint64(len(splitPkts))
		}
	}

	// 4. TLS record split
	if strat.TLSRecordSplit && protocol.IsTLS(packet) {
		// Находим начало TLS payload
		ipHdrLen := int(packet[0]&0x0F) * 4
		tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
		tlsPayload := packet[ipHdrLen+tcpHdrLen:]

		tlsPkts, err := pm.ApplyTLSSplit(tlsPayload, strat.TLSRecordSize)

		if err == nil && len(tlsPkts) > 0 {
			// Оборачиваем каждый фрагмент обратно в IP+TCP
			wrapped := make([][]byte, 0, len(tlsPkts))
			currentSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])

			for _, frag := range tlsPkts {
				fragLen := len(frag)
				if fragLen == 0 {
					continue
				}

				newPkt := make([]byte, ipHdrLen+tcpHdrLen+fragLen)
				copy(newPkt, packet[:ipHdrLen+tcpHdrLen]) // IP + TCP header

				// Обновляем IP total length
				binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))

				// Sequence number
				binary.BigEndian.PutUint32(newPkt[ipHdrLen+4:], currentSeq)

				copy(newPkt[ipHdrLen+tcpHdrLen:], frag)

				// DF bit off
				newPkt[6] &= ^byte(0x40)

				wrapped = append(wrapped, newPkt)
				currentSeq += uint32(fragLen)
			}

			packets = append(packets, wrapped...)
			pm.stats.SplitCount += uint64(len(wrapped))
			pm.stats.PacketsModified += uint64(len(wrapped))
		}
	}

	result := &ModifyResult{
		StrategyID:      strat.ID,
		SendOriginal:    true,
		ModifiedPackets: packets,
	}

	// Пересчитываем checksum для всех пакетов в конце
	for _, pkt := range packets {
		recalculateIPChecksum(pkt)
		FixTCPChecksum(pkt)
	}

	// Сортировка по sequence number (после всех мод, не ломает disorder, т.к. seq рассчитаны increasing)
	//sort.Slice(packets, func(i, j int) bool {
	//	if len(packets[i]) < tcpHdrOffset+8 || len(packets[j]) < tcpHdrOffset+8 {
	//		return false
	//	}
	//	seqI := binary.BigEndian.Uint32(packets[i][tcpHdrOffset+4:])
	//	seqJ := binary.BigEndian.Uint32(packets[j][tcpHdrOffset+4:])
	//	return seqI < seqJ
	//})

	pm.stats.PacketsModified += uint64(len(packets))

	return result, nil
}

// GetStats возвращает статистику
func (pm *PacketModifier) GetStats() ModifierStats {
	return pm.stats
}

// validatePacket проверяет, что пакет можно модифицировать
func validatePacket(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}

	// Проверяем IPv4
	if packet[0]>>4 != 4 {
		return fmt.Errorf("not IPv4")
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHeaderLen {
		return fmt.Errorf("packet truncated")
	}

	// Проверяем общую длину
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) {
		return fmt.Errorf("length mismatch: header=%d, actual=%d", totalLen, len(packet))
	}

	return nil
}
