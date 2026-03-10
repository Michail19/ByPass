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

// ModifyPacket главная функция модификации пакета.
//
// Порядок применения и приоритеты (по аналогии с zapret):
//
//	Уровень 1 — Fake:    всегда применяется если FakeMode != None
//	Уровень 2 — Disorder: применяется если DisorderMode != None; при этом Split НЕ применяется
//	                       (disorder уже делает разбивку с decoy-сегментом)
//	Уровень 3 — Split:   применяется только если Disorder не активен
//	Уровень 4 — TLSSplit: применяется только если Split не активен
//
// Применять все четыре одновременно нельзя: это создаёт 10+ пакетов вместо 1,
// вызывает burst, retransmission и slowdown.
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
	if strat == nil || strat.ID == 1 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	var packets [][]byte

	// Используем безопасную проверку ClientHello через полноценный TLS parser
	isClientHello := isClientHelloPacket(packet, payloadOffset, payloadLen)

	// Уровень 1: Fake — независим, всегда первый
	if strat.FakeMode != strategy.FakeNone {
		fakeRepeats := strat.Repeats
		if fakeRepeats <= 0 {
			fakeRepeats = 1
		}
		for rep := 0; rep < fakeRepeats; rep++ {
			fakePkts, err := pm.ApplyFake(packet, strat.FakePos, strat.FakeTTL, strat.FakeMode, strat.Fooling)
			if err == nil && len(fakePkts) > 0 {
				packets = append(packets, fakePkts...)
				pm.stats.FakeCount += uint64(len(fakePkts))
			}
		}
	}

	// Уровень 2: Disorder — если активен, Split и TLSSplit не применяем.
	// Disorder уже делает разбивку с decoy; двойная разбивка создаёт burst.
	if strat.DisorderMode != strategy.DisorderNone {
		disorderPkts, err := pm.ApplyDisorder(packet, strat.DisorderPos, strat.DisorderTTL, strat.DisorderMode)
		if err == nil && len(disorderPkts) > 0 {
			packets = append(packets, disorderPkts...)
			pm.stats.DisorderCount += uint64(len(disorderPkts))
		}
		// Disorder активен — пропускаем Split и TLSSplit
		goto finalize
	}

	// Уровень 3: Split — применяем только к ClientHello (TLS handshake)
	if strat.SplitMode != strategy.SplitNone && isClientHello {
		splitPkts, err := pm.ApplySplit(packet, strat.SplitPositions, strat.SplitSNIOffset)
		if err == nil && len(splitPkts) > 0 {
			packets = append(packets, splitPkts...)
			pm.stats.SplitCount += uint64(len(splitPkts))
			// Split активен — пропускаем TLSSplit
			goto finalize
		}
	}

	// Уровень 4: TLS record split — только если Split не применился
	if strat.TLSRecordSplit && protocol.IsTLS(packet) {
		tlsPayload := packet[ipHdrLen+tcpHdrLen:]
		tlsPkts, err := pm.ApplyTLSSplit(tlsPayload, strat.TLSRecordSize)
		if err == nil && len(tlsPkts) > 1 { // > 1: реально было разбито
			currentSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
			for _, frag := range tlsPkts {
				fragLen := len(frag)
				if fragLen == 0 {
					continue
				}
				newPkt := make([]byte, ipHdrLen+tcpHdrLen+fragLen)
				copy(newPkt, packet[:ipHdrLen+tcpHdrLen])
				binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
				binary.BigEndian.PutUint32(newPkt[ipHdrLen+4:], currentSeq)
				copy(newPkt[ipHdrLen+tcpHdrLen:], frag)
				newPkt[6] &= ^byte(0x40) // clear DF
				packets = append(packets, newPkt)
				pm.stats.SplitCount++
				currentSeq += uint32(fragLen)
			}
		}
	}

finalize:
	// Пересчитываем checksum для всех пакетов
	for _, pkt := range packets {
		recalculateIPChecksum(pkt)
		// FixTCPChecksum не вызываем для FakeBadSum — checksum намеренно испорчен.
		// ApplyFake для FakeBadSum уже возвращает готовый пакет без повторного расчёта.
		if len(pkt) >= 20 && pkt[9] == 6 {
			ipHL := int(pkt[0]&0x0F) * 4
			tcpOff := ipHL + 16
			// Проверяем: если checksum уже нулевой после XOR — это FakeBadSum, не трогаем
			isZeroedChecksum := pkt[tcpOff] == 0x00 && pkt[tcpOff+1] == 0x00
			if !isZeroedChecksum {
				FixTCPChecksum(pkt)
			}
		}
	}

	pm.stats.PacketsModified += uint64(len(packets))

	return &ModifyResult{
		StrategyID:      strat.ID,
		SendOriginal:    true,
		ModifiedPackets: packets,
	}, nil
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
	if packet[0]>>4 != 4 {
		return fmt.Errorf("not IPv4")
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHeaderLen {
		return fmt.Errorf("packet truncated")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) {
		return fmt.Errorf("length mismatch: header=%d, actual=%d", totalLen, len(packet))
	}
	return nil
}

// isClientHelloPacket определяет, содержит ли пакет TLS ClientHello.
//
// Старый однострочный check:
//
//	packet[payloadOffset+5] == 0x01
//
// Проблема: TLS record и Handshake message не всегда совпадают.
// Один TLS record может содержать несколько Handshake messages,
// или ClientHello может быть фрагментировано по нескольким записям.
//
// Этот парсер проверяет:
//  1. TLS record header: ContentType=0x16 (Handshake), version 0x0301–0x0304
//  2. TLS record length совпадает с фактическим payload
//  3. Handshake type = 0x01 (ClientHello)
//  4. Handshake length разумный (не нулевой и помещается в record)
func isClientHelloPacket(packet []byte, payloadOffset, payloadLen int) bool {
	if payloadLen < 9 { // TLS record(5) + Handshake header(4) minimum
		return false
	}
	p := packet[payloadOffset:]

	// TLS record ContentType: 0x16 = Handshake
	if p[0] != 0x16 {
		return false
	}
	// TLS version: 0x0301 (TLS 1.0 record layer) – 0x0304 (TLS 1.3)
	// ClientHello всегда использует 0x0301 в record layer даже для TLS 1.3
	if p[1] != 0x03 || p[2] > 0x04 {
		return false
	}
	// TLS record length
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	if recordLen < 4 || 5+recordLen > len(p) {
		return false // фрагментированный или некорректный record
	}
	// Handshake type: 0x01 = ClientHello
	if p[5] != 0x01 {
		return false
	}
	// Handshake message length (3 байта big-endian)
	hsLen := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if hsLen == 0 || hsLen > recordLen-4 {
		return false
	}
	return true
}
