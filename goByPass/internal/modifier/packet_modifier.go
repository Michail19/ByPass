package modifier

import (
	"cache"
	"conntrack"
	"encoding/binary"
	"mydpi/internal/protocol"
	"mydpi/internal/strategy"
)

// PacketModifier реализует модификацию пакетов
type PacketModifier struct {
	strategyManager *strategy.Manager
	ipCache         *cache.IPCache
}

// ModifyResult содержит результат модификации
type ModifyResult struct {
	ModifiedPackets [][]byte // модифицированные версии пакета
	SendOriginal    bool     // нужно ли отправлять оригинал
	Delay           int      // задержка перед отправкой (ms)
}

// ApplySplit применяет разбиение пакета
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int) [][]byte {
	var fragments [][]byte
	lastPos := 0

	for _, pos := range splitPos {
		if pos < len(packet) {
			fragments = append(fragments, packet[lastPos:pos])
			lastPos = pos
		}
	}

	if lastPos < len(packet) {
		fragments = append(fragments, packet[lastPos:])
	}

	return fragments
}

// ApplyDisorder применяет нарушение порядка
func (pm *PacketModifier) ApplyDisorder(packet []byte, disorderPos []int, ttl int) [][]byte {
	// Создаем копию пакета с низким TTL
	disorderPacket := make([]byte, len(packet))
	copy(disorderPacket, packet)

	// Здесь модифицируем IP-заголовок, устанавливая TTL
	// ... сложная работа с raw sockets

	return [][]byte{disorderPacket, packet}
}

// ApplyFake создает поддельный пакет
func (pm *PacketModifier) ApplyFake(packet []byte, fakePos int, fakeTTL int, fakeMode strategy.FakeMode) [][]byte {
	fakePacket := make([]byte, len(packet))
	copy(fakePacket, packet)

	// Изменяем часть пакета на фейковые данные
	// или добавляем TCP опции (MD5 signature и т.д.)

	return [][]byte{fakePacket, packet}
}

// ModifyPacket главная функция модификации
func (pm *PacketModifier) ModifyPacket(packet []byte, flow *conntrack.Flow) *ModifyResult {
	result := &ModifyResult{
		SendOriginal: true,
	}

	// Определяем стратегию для этого потока
	strat := pm.strategyManager.SelectStrategy(flow.DstIP, "")

	// Применяем модификации в зависимости от стратегии
	if strat.Split != strategy.SplitNone {
		fragments := pm.ApplySplit(packet, strat.SplitPos)
		result.ModifiedPackets = append(result.ModifiedPackets, fragments...)
		result.SendOriginal = false
	}

	if strat.Disorder != strategy.DisorderNone {
		disorderPkts := pm.ApplyDisorder(packet, strat.DisorderPos, strat.DisorderTTL)
		result.ModifiedPackets = append(result.ModifiedPackets, disorderPkts...)
	}

	if strat.Fake != strategy.FakeNone {
		fakePkts := pm.ApplyFake(packet, strat.FakePos, strat.FakeTTL, strat.Fake)
		result.ModifiedPackets = append(result.ModifiedPackets, fakePkts...)
	}

	return result
}
