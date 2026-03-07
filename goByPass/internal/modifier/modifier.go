package modifier

import (
	"ByPass/internal/cache"
	"ByPass/internal/conntrack"
	"ByPass/internal/protocol"
	"ByPass/internal/strategy"
	"encoding/binary"
	"fmt"
	"log"
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
	if packet == nil || len(packet) < 40 { // Минимум: IPv4 + TCP
		return &ModifyResult{SendOriginal: true}, nil
	}

	pm.stats.PacketsProcessed++

	// Быстрый early exit, если пакет не IPv4 или не TCP
	if packet[0]>>4 != 4 || packet[9] != 6 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	// Парсим заголовки один раз
	ipHeaderLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHeaderLen+20 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	tcpHeaderOffset := ipHeaderLen
	tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4
	if tcpHeaderLen < 20 || len(packet) < tcpHeaderOffset+tcpHeaderLen {
		return &ModifyResult{SendOriginal: true}, nil
	}

	payloadOffset := tcpHeaderOffset + tcpHeaderLen
	//payloadLen := len(packet) - payloadOffset

	dstIP := flow.GetDstIP()

	// Выбор стратегии
	strat := pm.strategyManager.SelectStrategy(
		dstIP,
		flow.Hostname,
		int(flow.GetDstPort()),
		"tcp",
	)

	if strat == nil {
		return &ModifyResult{SendOriginal: true}, nil
	}

	result := &ModifyResult{
		StrategyID:   strat.ID,
		SendOriginal: true,
	}

	// Флаг, что мы уже что-то модифицировали и оригинал отправлять не нужно
	var modified bool

	// 1. TLS Record Split (приоритетный, если включён)
	if strat.TLSRecordSplit && protocol.IsTLS(packet) {
		config := &TLSSplitConfig{
			Enabled:        true,
			RecordSize:     strat.TLSRecordSize,
			SplitHandshake: true,
			SplitAlert:     true,
		}

		tlsFragments, err := pm.ApplyTLSSplit(packet, config)
		if err == nil && len(tlsFragments) > 0 {
			var wrapped [][]byte
			currentSeq := binary.BigEndian.Uint32(packet[tcpHeaderOffset+4:])

			for _, frag := range tlsFragments {
				fragLen := len(frag)
				if fragLen == 0 {
					continue
				}

				newPkt := make([]byte, payloadOffset+fragLen)
				copy(newPkt, packet[:payloadOffset]) // IP + TCP header

				// Обновляем длину IP
				binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))

				// Обновляем sequence number
				binary.BigEndian.PutUint32(newPkt[tcpHeaderOffset+4:], currentSeq)

				// Копируем фрагмент TLS
				copy(newPkt[payloadOffset:], frag)

				// Сбрасываем DF-бит (если был)
				newPkt[6] &= ^byte(0x40)

				// Один раз пересчитываем checksum'ы
				recalculateIPChecksum(newPkt)
				if err := FixTCPChecksum(newPkt); err != nil {
					log.Printf("TLS-split checksum error: %v", err)
					continue
				}

				wrapped = append(wrapped, newPkt)
				currentSeq += uint32(fragLen)
			}

			if len(wrapped) > 0 {
				result.ModifiedPackets = append(result.ModifiedPackets, wrapped...)
				modified = true
				result.SendOriginal = false
				pm.stats.SplitCount += uint64(len(wrapped))
				pm.stats.PacketsModified += uint64(len(wrapped))
			}
		}
	}

	// 2. TCP Segmentation (SplitMode)
	if !modified && strat.SplitMode != strategy.SplitNone {
		fragments, err := pm.ApplySplit(packet, strat.SplitPositions, strat.SplitSNIOffset)
		if err == nil && len(fragments) > 0 {
			result.ModifiedPackets = append(result.ModifiedPackets, fragments...)
			modified = true
			result.SendOriginal = false
			pm.stats.SplitCount += uint64(len(fragments))
			pm.stats.PacketsModified += uint64(len(fragments))
		}
	}

	// 3. Disorder
	if !modified && strat.DisorderMode != strategy.DisorderNone {
		disorderPkts, err := pm.ApplyDisorder(packet, strat.DisorderPos, strat.DisorderTTL)
		if err == nil && len(disorderPkts) > 0 {
			result.ModifiedPackets = append(result.ModifiedPackets, disorderPkts...)
			modified = true
			pm.stats.DisorderCount += uint64(len(disorderPkts))
			pm.stats.PacketsModified += uint64(len(disorderPkts))
		}
	}

	// 4. Fake packets (обычно отправляются вместе с оригиналом)
	if strat.FakeMode != strategy.FakeNone {
		fakePkts, err := pm.ApplyFake(packet, strat.FakePos, strat.FakeTTL, strat.FakeMode)
		if err == nil && len(fakePkts) > 0 {
			result.ModifiedPackets = append(result.ModifiedPackets, fakePkts...)
			pm.stats.FakeCount += uint64(len(fakePkts))
			pm.stats.PacketsModified += uint64(len(fakePkts))
			// Fake-пакеты обычно идут ДО оригинала → SendOriginal остаётся true
		}
	}

	// Если ничего не применили — отправляем оригинал
	if len(result.ModifiedPackets) == 0 {
		result.SendOriginal = true
	}

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
