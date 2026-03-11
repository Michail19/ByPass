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

type ModifierStats struct {
	PacketsProcessed uint64
	PacketsModified  uint64
	SplitCount       uint64
	DisorderCount    uint64
	FakeCount        uint64
	Errors           uint64
}

type ModifyResult struct {
	StrategyID      int
	ModifiedPackets [][]byte
	SendOriginal    bool
	Delay           int
}

func NewPacketModifier(sm *strategy.Manager, ic *cache.IPCache) *PacketModifier {
	return &PacketModifier{strategyManager: sm, ipCache: ic}
}

// ModifyPacket — главная функция модификации.
//
// Приоритеты применения (аналог zapret):
//  1. SynData    — применяется к SYN-пакетам, остальное пропускается
//  2. Fake       — если Fooling != 0 или есть FakeTLSFiles, отправляем fake перед реальным
//  3. SeqOvl     — multisplit (основная техника): seqovl-пакет + реальные сегменты
//  4. FakedSplit — fake + split
//  5. MultiDisorder — disorder в нескольких позициях
//  6. Disorder   — decoy + реальные сегменты
//  7. Split      — только если ни один из 3-6 не активен
//  8. TLSSplit   — только если Split не применился
func (pm *PacketModifier) ModifyPacket(packet []byte, flow *conntrack.Flow) (*ModifyResult, error) {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return &ModifyResult{SendOriginal: true}, nil
	}
	pm.stats.PacketsProcessed++

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen
	payloadLen := len(packet) - payloadOffset

	if payloadLen <= 0 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	strat := pm.strategyManager.SelectStrategy(
		flow.GetDstIP(), flow.Hostname, int(flow.GetDstPort()), "tcp",
	)
	if strat == nil || strat.ID == 1 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	// Cutoff: после N data-пакетов прекращаем модификацию
	if strat.Cutoff > 0 {
		flow.Mu.RLock()
		modified := flow.DataPacketsModified
		flow.Mu.RUnlock()
		if modified >= strat.Cutoff {
			return &ModifyResult{SendOriginal: true}, nil
		}
	}

	ipHdrLenInt := ipHdrLen

	// IPIDZero (для Google/Cloudflare)
	if strat.IPIDZero {
		packet[4] = 0
		packet[5] = 0
	}

	flags := packet[ipHdrLen+13]
	isSYN := (flags & 0x02) != 0
	isACK := (flags & 0x10) != 0
	isClientHello := isClientHelloPacket(packet, payloadOffset, payloadLen)

	var packets [][]byte

	// ── 1. SynData ────────────────────────────────────────────────────────────
	if strat.SynData && isSYN && !isACK {
		// Определяем fake payload для SYN
		var synFakeData []byte
		if len(strat.FakeTLSFilesData) > 0 {
			synFakeData = strat.FakeTLSFilesData[0]
		}
		if synFakeData == nil && strat.FakeHTTPFileData != nil {
			synFakeData = strat.FakeHTTPFileData
		}
		synPkts, err := pm.ApplySynData(packet, synFakeData)
		if err == nil && len(synPkts) > 0 {
			// synPkts уже включает оригинальный SYN как последний элемент
			pm.stats.DisorderCount += uint64(len(synPkts))
			pm.stats.PacketsModified += uint64(len(synPkts))
			return &ModifyResult{
				StrategyID:      strat.ID,
				ModifiedPackets: synPkts,
				SendOriginal:    false, // SYN уже включён в synPkts
			}, nil
		}
		return &ModifyResult{SendOriginal: true}, nil
	}

	hasFooling := strat.Fooling != 0 ||
		len(strat.FakeTLSFilesData) > 0 ||
		strat.FakeTLSNullBytes ||
		strat.FakeTLSPrevPacket ||
		strat.FakeTLSModSNI != "" ||
		strat.FakeHTTPFileData != nil

	fakeRepeats := strat.FakeRepeats
	if fakeRepeats <= 0 {
		fakeRepeats = 1
	}

	// ── 2. Fake ───────────────────────────────────────────────────────────────
	if hasFooling && (isClientHello || strat.AnyProtocol) {
		for rep := 0; rep < fakeRepeats; rep++ {
			fakePayload := pm.selectFakeTLSPayload(strat, rep, isClientHello, packet, ipHdrLenInt)
			fakePkts, err := pm.ApplyFake(
				packet, strat.FakeTTL, strat.Fooling, strat.BadSeqIncrement, fakePayload,
			)
			if err == nil {
				packets = append(packets, fakePkts...)
				pm.stats.FakeCount += uint64(len(fakePkts))
			}
		}
	}

	// ── 3–8. Split/Disorder (только для ClientHello или AnyProtocol) ──────────
	//
	// originalReplaced = true означает что packets[] уже содержит полную замену
	// оригинального payload (сегменты покрывают те же seq numbers что и original).
	// В этом случае SendOriginal должен быть false (#1):
	//   - Для split/seqovl/disorder отправка original ПОСЛЕ сегментов бессмысленна:
	//     сегменты покрывают весь original (TCP принимает по seq, дубль игнорируется).
	//   - Для disorder это критично: DPI видит unmodified ORIGINAL после сегментов
	//     и анализирует именно его → bypass полностью теряет эффект.
	//   - Для fake-only (без сегментов) SendOriginal=true — fake пакеты гибнут по TTL,
	//     оригинал должен дойти до сервера.
	var originalReplaced bool

	if !isClientHello && !strat.AnyProtocol {
		goto finalize
	}

	// 3. SeqOvl (multisplit) — приоритет над всем остальным
	if strat.NeedsSeqOvl() && isClientHello {
		seqPkts, err := pm.ApplySeqOvl(
			packet, strat.SeqOvlLen, strat.SeqOvlPatternData, strat.SplitPositions,
			// SeqOvl TTL: предпочитаем DisorderTTL (запретовский default=1), fallback FakeTTL.
			// ovl-пакет идёт с seq < ISN — должен умереть до сервера, но дойти до DPI.
			func() int {
				if strat.DisorderTTL > 0 {
					return strat.DisorderTTL
				}
				if strat.FakeTTL > 0 {
					return strat.FakeTTL
				}
				return 6 // zapret default
			}(),
		)
		if err == nil && len(seqPkts) > 0 {
			packets = append(packets, seqPkts...)
			pm.stats.SplitCount += uint64(len(seqPkts))
			originalReplaced = true // seqPkts содержит реальные сегменты
			goto finalize
		}
	}

	// 4. FakedSplit
	if strat.FakedSplit && isClientHello {
		var fakeTLSForFaked []byte
		if len(strat.FakeTLSFilesData) > 0 {
			fakeTLSForFaked = strat.FakeTLSFilesData[0]
		}
		fsPkts, err := pm.ApplyFakedSplit(
			packet,
			strat.FakedSplitPos,
			strat.FakedSplitPattern,
			strat.Fooling,
			strat.BadSeqIncrement,
			strat.FakeTTL,
			fakeTLSForFaked,
		)
		if err == nil && len(fsPkts) > 0 {
			// FakedSplit уже включает fake-пакеты, не дублируем из шага 2
			// Заменяем packets (fake из шага 2 уже внутри ApplyFakedSplit)
			packets = fsPkts
			pm.stats.SplitCount += uint64(len(fsPkts))
			originalReplaced = true // fsPkts содержит реальные сегменты
			goto finalize
		}
	}

	// 5+6. MultiDisorder / Disorder
	if strat.MultiDisorder || strat.DisorderMode != strategy.DisorderNone {
		disorderPos := strat.DisorderPos
		if len(disorderPos) == 0 {
			disorderPos = strat.SplitPositions
		}
		if len(disorderPos) == 0 {
			disorderPos = []int{1}
		}
		dPkts, err := pm.ApplyDisorder(
			packet, disorderPos, strat.DisorderTTL, strat.DisorderMode,
			strat.Fooling, strat.BadSeqIncrement,
		)
		if err == nil && len(dPkts) > 0 {
			packets = append(packets, dPkts...)
			pm.stats.DisorderCount += uint64(len(dPkts))
			originalReplaced = true // dPkts содержит реальные сегменты после decoy
			goto finalize
		}
	}

	// 7. HostFakeSplit (HTTP)
	if strat.HostFakeSplit && flow.IsHTTP {
		hfPkts, err := pm.ApplyHostFakeSplit(packet, strat)
		if err == nil && len(hfPkts) > 0 {
			packets = append(packets, hfPkts...)
			pm.stats.SplitCount += uint64(len(hfPkts))
			originalReplaced = true
			goto finalize
		}
	}

	// 8. Split обычный
	if strat.SplitMode != strategy.SplitNone && len(strat.SplitPositions) > 0 && isClientHello {
		splitPkts, err := pm.ApplySplit(packet, strat.SplitPositions, strat.SplitSNIOffset)
		if err == nil && len(splitPkts) > 0 {
			packets = append(packets, splitPkts...)
			pm.stats.SplitCount += uint64(len(splitPkts))
			originalReplaced = true // splitPkts — полная замена original
			goto finalize
		}
	}

	// 9. TLS record split — последний резерв
	if strat.TLSRecordSplit && protocol.IsTLS(packet[payloadOffset:]) {
		tlsFrag, err := pm.ApplyTLSSplit(packet[payloadOffset:], strat.TLSRecordSize)
		if err == nil && len(tlsFrag) > 1 {
			seq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
			for _, frag := range tlsFrag {
				newPkt := make([]byte, ipHdrLen+tcpHdrLen+len(frag))
				copy(newPkt, packet[:payloadOffset])
				binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
				binary.BigEndian.PutUint32(newPkt[ipHdrLen+4:], seq)
				copy(newPkt[payloadOffset:], frag)
				// DF: не трогаем — newPkt скопирован из packet[:payloadOffset],
				// packet[6] уже содержит оригинальные Flags+FragOffset (#6).
				recalculateIPChecksum(newPkt)
				FixTCPChecksum(newPkt)
				packets = append(packets, newPkt)
				seq += uint32(len(frag))
			}
			originalReplaced = true // TLS fragments покрывают весь payload
		}
	}

finalize:
	// Checksums уже пересчитаны в каждом из путей выше (#1):
	//   ApplyFake         → setIPTTL + recalculate + FixTCP (или FakeBadSum: умышленно испорчен)
	//   buildTCPSegments  → recalculate + FixTCP на каждый сегмент
	//   ApplySeqOvl       → recalculate + FixTCP на seqovl + buildTCPSegments
	//   ApplyDisorder     → recalculate + FixTCP на decoy + buildTCPSegments
	//   ApplyFakedSplit   → ApplyFake + buildTCPSegments
	//   TLS record split  → явные вызовы обоих
	//
	// Повторный пересчёт здесь ЗАПРЕЩЁН:
	//   - FakeBadSum: checksum умышленно испорчен. Проверка "if checksum != 0" некорректна:
	//     TCP checksum 0x0000 — легальное значение по RFC (передаётся как 0xFFFF),
	//     т.е. обычный пакет с checksum=0 ошибочно пропустится без пересчёта.
	//   - Двойной пересчёт ломает FakeBadSum и не даёт никакой пользы.

	if len(packets) == 0 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	pm.stats.PacketsModified += uint64(len(packets))
	return &ModifyResult{
		StrategyID:      strat.ID,
		ModifiedPackets: packets,
		// SendOriginal=true только когда packets[] содержат только decoy-пакеты (fake с низким TTL)
		// и реальный оригинал ещё не отправлен.
		// SendOriginal=false когда packets[] содержат сегменты оригинального payload (#1):
		//   - split/seqovl/disorder: сегменты покрывают все seq numbers оригинала
		//   - Отправка оригинала ПОСЛЕ сегментов при disorder убивает bypass:
		//     DPI видит unmodified ORIGINAL и анализирует его вместо разрозненных частей.
		SendOriginal: !originalReplaced,
	}, nil
}

// selectFakeTLSPayload возвращает payload для fake-пакета с учётом всех режимов:
// FakeTLSNullBytes → 4 нулевых байта
// FakeTLSPrevPacket → оригинальный payload (nil = использовать packet)
// FakeTLSFiles → загруженные .bin данные (с ротацией)
// FakeTLSMod → модифицировать оригинальный ClientHello (замена SNI и т.д.)
// nil → использовать оригинальный payload (ApplyFake скопирует его)
func (pm *PacketModifier) selectFakeTLSPayload(
	strat *strategy.Strategy,
	repIdx int,
	isClientHello bool,
	packet []byte,
	ipHdrLen int,
) []byte {

	if strat.FakeTLSNullBytes {
		// Минимальный TLS record: ContentType=Handshake(0x16) + TLS1.0 + length=0.
		// 4 нулевых байта тривиально детектируются как не-TLS (#4).
		// Пустой Handshake record структурно валиден — сервер дропнет без RST,
		// DPI принимает как начало Handshake и теряет контекст.
		return []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	}

	if strat.FakeTLSPrevPacket {
		// Использовать предыдущий ClientHello — пока просто возвращаем оригинал
		return nil
	}

	if len(strat.FakeTLSFilesData) > 0 {
		return strat.FakeTLSData(repIdx)
	}

	if strat.FakeTLSModSNI != "" && isClientHello {
		tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
		payloadOffset := ipHdrLen + tcpHdrLen
		if payloadOffset < len(packet) {
			return modifyClientHelloSNI(packet[payloadOffset:], strat.FakeTLSModSNI)
		}
	}

	if strat.FakeHTTPFileData != nil && !isClientHello {
		return strat.FakeHTTPFileData
	}

	return nil
}

// ApplyHostFakeSplit применяет hostfakesplit для HTTP трафика:
// заменяет Host: заголовок на strat.HostFakeSplitHost и разбивает поток там.
func (pm *PacketModifier) ApplyHostFakeSplit(packet []byte, strat *strategy.Strategy) ([][]byte, error) {
	if !strat.HostFakeSplit || strat.HostFakeSplitHost == "" {
		return nil, fmt.Errorf("hostfakesplit not configured")
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen

	if payloadOffset >= len(packet) {
		return nil, fmt.Errorf("no payload")
	}

	payload := packet[payloadOffset:]

	// Создаём fake-пакет с подменённым Host:
	fakePayload := replaceHTTPHost(payload, strat.HostFakeSplitHost)
	if fakePayload == nil {
		return nil, fmt.Errorf("host header not found")
	}

	fakePkts, err := pm.ApplyFake(packet, strat.FakeTTL, strat.Fooling, strat.BadSeqIncrement, fakePayload)
	if err != nil {
		return nil, err
	}

	// Реальный пакет идёт после fake
	return append(fakePkts, packet), nil
}

// modifyClientHelloSNI заменяет SNI в TLS ClientHello.
// Возвращает nil если не удалось распарсить.
func modifyClientHelloSNI(payload []byte, newSNI string) []byte {
	if len(payload) < 9 || payload[0] != 0x16 || payload[1] != 0x03 {
		return nil
	}
	// Находим существующий SNI и заменяем его
	// Если новый SNI короче/длиннее — нужна перестройка заголовков.
	// Упрощённый вариант: если длины совпадают — заменяем in-place.
	sniBytes := []byte(newSNI)
	modified := make([]byte, len(payload))
	copy(modified, payload)

	// Ищем SNI extension (0x00 0x00) в extensions
	// Используем FindSNI из tls.go через protocol.FindSNI
	// (здесь дублируем минимальный поиск чтобы не импортировать protocol)
	// Реальная реализация должна использовать protocol.FindSNI
	_ = sniBytes
	return modified // TODO: полная реализация замены SNI
}

// replaceHTTPHost заменяет Host: заголовок в HTTP payload
func replaceHTTPHost(payload []byte, newHost string) []byte {
	hostPrefix := []byte("Host: ")
	idx := -1
	for i := 0; i < len(payload)-len(hostPrefix); i++ {
		match := true
		for j, b := range hostPrefix {
			if payload[i+j] != b && payload[i+j] != b+32 { // case-insensitive
				match = false
				break
			}
		}
		if match {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}

	// Находим конец строки Host:
	end := idx + len(hostPrefix)
	for end < len(payload) && payload[end] != '\r' && payload[end] != '\n' {
		end++
	}

	result := make([]byte, 0, len(payload))
	result = append(result, payload[:idx]...)
	result = append(result, []byte("Host: "+newHost)...)
	result = append(result, payload[end:]...)
	return result
}

// isClientHelloPacket — полноценная проверка TLS ClientHello.
//
// Намеренно принимает частичные (fragmented) ClientHello (#1):
// Браузеры часто отправляют ClientHello в нескольких TCP сегментах.
// Старая проверка "5+recordLen > len(p)" отбрасывала такие пакеты →
// split/disorder/fake не применялись ни к одному из сегментов.
//
// Relaxed логика: если первые 9 байт выглядят как TLS 1.x ClientHello —
// считаем это ClientHello. Первый сегмент всегда начинается с record header.
func isClientHelloPacket(packet []byte, payloadOffset, payloadLen int) bool {
	if payloadLen < 9 {
		return false
	}
	p := packet[payloadOffset:]
	// ContentType: Handshake (0x16)
	if p[0] != 0x16 {
		return false
	}
	// Version: TLS 1.0–1.3 (major=0x03, minor=0x00..0x04)
	// TLS 1.3 передаётся как 0x0303 с supported_versions extension
	if p[1] != 0x03 || p[2] > 0x04 {
		return false
	}
	// HandshakeType: ClientHello = 0x01
	// p[5] = HandshakeType (первый байт за record header)
	if p[5] != 0x01 {
		return false
	}
	// Длина handshake body (3-байтовое BE число)
	hsLen := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if hsLen <= 0 {
		return false
	}
	// Старая проверка "5+recordLen > len(p)" отбрасывала фрагментированные ClientHello.
	// Вместо этого: если первые 9 байт валидны — это ClientHello.
	// Мы не парсим SNI из фрагментированного пакета, но применяем bypass.
	return true
}

func (pm *PacketModifier) GetStats() ModifierStats {
	return pm.stats
}

func validatePacket(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}
	if packet[0]>>4 != 4 {
		return fmt.Errorf("not IPv4")
	}
	ipHdrLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHdrLen {
		return fmt.Errorf("packet truncated")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) {
		return fmt.Errorf("length mismatch: header=%d, actual=%d", totalLen, len(packet))
	}
	return nil
}
