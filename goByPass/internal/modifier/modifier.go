package modifier

import (
	"ByPass/internal/cache"
	"ByPass/internal/conntrack"
	"ByPass/internal/strategy"
	"errors"
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
