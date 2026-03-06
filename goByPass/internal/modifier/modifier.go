package modifier

import (
	"ByPass/internal/cache"
	"ByPass/internal/conntrack"
	"ByPass/internal/protocol"
	"ByPass/internal/strategy"
	"encoding/binary"
	"errors"
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

// ModifyPacket главная функция модификации
func (pm *PacketModifier) ModifyPacket(packet []byte, flow *conntrack.Flow) (*ModifyResult, error) {
	if packet == nil || len(packet) == 0 {
		return nil, errors.New("empty packet")
	}

	pm.stats.PacketsProcessed++

	// Получаем IP назначения из потока
	dstIP := flow.GetDstIP()

	// Определяем стратегию для этого потока
	strat := pm.strategyManager.SelectStrategy(
		dstIP,
		flow.Hostname,
		int(flow.GetDstPort()),
		"tcp",
	)

	if strat == nil {
		// Нет стратегии - пропускаем без изменений
		return &ModifyResult{
			SendOriginal: true,
		}, nil
	}

	result := &ModifyResult{
		StrategyID:   strat.ID, // сохраняем ID стратегии
		SendOriginal: true,
	}

	// Применяем модификации в зависимости от стратегии
	if strat.SplitMode != strategy.SplitNone {
		fragments, err := pm.ApplySplit(packet, strat.SplitPositions, strat.SplitSNIOffset)
		if err == nil && len(fragments) > 0 {
			result.ModifiedPackets = append(result.ModifiedPackets, fragments...)
			result.SendOriginal = false
			pm.stats.SplitCount++
			pm.stats.PacketsModified++
		}
	}

	// Добавляем TLS-split если включено и пакет TLS
	if strat.TLSRecordSplit && protocol.IsTLS(packet) {
		config := &TLSSplitConfig{
			Enabled:        true,
			RecordSize:     strat.TLSRecordSize,
			SplitHandshake: true,
			SplitAlert:     true,
		}
		tlsFragments, err := pm.ApplyTLSSplit(packet, config)
		if err == nil && len(tlsFragments) > 0 {
			// Для TLS-split нужно обернуть каждый фрагмент в IP+TCP (упрощённо: отправляем как отдельные пакеты с теми же headers, но корректируем seq)
			// Здесь упрощённо добавляем как есть; в pipeline нужно доработать отправку с корректировкой seq
			result.ModifiedPackets = append(result.ModifiedPackets, tlsFragments...)
			result.SendOriginal = false
			pm.stats.SplitCount++
			pm.stats.PacketsModified++
		}
	}

	if strat.DisorderMode != strategy.DisorderNone {
		disorderPkts, err := pm.ApplyDisorder(packet, strat.DisorderPos, strat.DisorderTTL)
		if err == nil && len(disorderPkts) > 0 {
			result.ModifiedPackets = append(result.ModifiedPackets, disorderPkts...)
			pm.stats.DisorderCount++
			pm.stats.PacketsModified++
		}
	}

	if strat.FakeMode != strategy.FakeNone {
		fakePkts, err := pm.ApplyFake(packet, strat.FakePos, strat.FakeTTL, strat.FakeMode)
		if err == nil && len(fakePkts) > 0 {
			result.ModifiedPackets = append(result.ModifiedPackets, fakePkts...)
			pm.stats.FakeCount++
			pm.stats.PacketsModified++
		}
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
