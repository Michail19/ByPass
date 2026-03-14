package modifier

import (
	"ByPass/internal/cache"
	"ByPass/internal/conntrack"
	"ByPass/internal/protocol"
	"ByPass/internal/strategy"
	"bytes"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

// PacketModifier реализует модификацию пакетов
type PacketModifier struct {
	strategyManager *strategy.Manager
	ipCache         *cache.IPCache
	stats           ModifierStats
}

// ModifierStats — статистика модификатора.
// Все поля atomic.Uint64: ModifyPacket вызывается из нескольких воркеров
// одновременно, обычный uint64++ — data race (#4 в review).
type ModifierStats struct {
	PacketsProcessed atomic.Uint64
	PacketsModified  atomic.Uint64
	SplitCount       atomic.Uint64
	DisorderCount    atomic.Uint64
	FakeCount        atomic.Uint64
	Errors           atomic.Uint64
}

// ModifierStatsSnapshot — иммутабельный снимок для логирования/UI.
type ModifierStatsSnapshot struct {
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
// strat — уже выбранная стратегия из pipeline.go (SelectStrategy вызван там).
// Передаём готовую стратегию чтобы избежать повторного вызова SelectStrategy
// внутри ModifyPacket: два независимых вызова могут вернуть разные стратегии
// при гонке с Discovery → непредсказуемое поведение (#DoubleSelect).
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
func (pm *PacketModifier) ModifyPacket(packet []byte, flow *conntrack.Flow, strat *strategy.Strategy) (*ModifyResult, error) {
	ipHdrLen, tcpHdrLen, payloadOffset, err := parseIPv4TCP(packet)
	if err != nil {
		return &ModifyResult{SendOriginal: true}, nil
	}
	pm.stats.PacketsProcessed.Add(1)

	payloadLen := len(packet) - payloadOffset
	flags := packet[ipHdrLen+13]
	isSYN := (flags & 0x02) != 0
	isACK := (flags & 0x10) != 0

	if strat == nil || strat.ID == 1 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	// IPIDZero (для Google/Cloudflare)
	if strat.IPIDZero {
		packet[4] = 0
		packet[5] = 0
	}

	isClientHello := isClientHelloPacket(packet, payloadOffset, payloadLen)

	var packets [][]byte

	// ── 1. SynData ────────────────────────────────────────────────────────────
	// ВАЖНО: этот блок ДОЛЖЕН быть до проверки payloadLen <= 0.
	// SYN-пакеты имеют payloadLen=0 — проверка ниже вернула бы {SendOriginal:true}
	// до достижения этого кода, и SynData никогда бы не сработал (#BugSynData).
	if strat.SynData && isSYN && !isACK {
		// Определяем fake payload для SYN
		var synFakeData []byte
		if len(strat.FakeTLSFilesData) > 0 {
			synFakeData = strat.FakeTLSFilesData[0]
		}
		if synFakeData == nil && strat.FakeHTTPFileData != nil {
			synFakeData = strat.FakeHTTPFileData
		}
		// Fake SYN должен умереть до сервера (DPI 2-3 hop, сервер 6+ hop).
		// Используем DisorderTTL (ALT5: 4), иначе FakeTTL, иначе default=4.
		synTTL := strat.DisorderTTL
		if synTTL <= 0 {
			synTTL = strat.FakeTTL
		}
		synPkts, err := pm.ApplySynData(packet, synFakeData, synTTL)
		if err != nil {
			pm.stats.Errors.Add(1)
			return &ModifyResult{SendOriginal: true}, nil
		}
		if len(synPkts) > 0 {
			// В synPkts теперь только fake SYN с низким TTL.
			// Реальный SYN должен уйти обычным Send(), а не SendModified().
			pm.stats.DisorderCount.Add(uint64(len(synPkts)))
			pm.stats.PacketsModified.Add(uint64(len(synPkts)))
			return &ModifyResult{
				StrategyID:      strat.ID,
				ModifiedPackets: synPkts,
				SendOriginal:    true,
			}, nil
		}
		return &ModifyResult{SendOriginal: true}, nil
	}

	// Все остальные техники требуют payload
	if payloadLen <= 0 {
		return &ModifyResult{SendOriginal: true}, nil
	}

	hasFooling := strat.Fooling != 0 ||
		len(strat.FakeTLSFilesData) > 0 ||
		strat.FakeTLSNullBytes ||
		strat.FakeTLSPrevPacket ||
		strat.FakeTLSModSNI != ""

	fakeRepeats := strat.FakeRepeats
	if fakeRepeats <= 0 {
		fakeRepeats = 1
	}

	// ── 2. Fake ───────────────────────────────────────────────────────────────
	// Fake
	if hasFooling && !strat.FakedSplit && (isClientHello || strat.AnyProtocol) {
		for rep := 0; rep < fakeRepeats; rep++ {
			fakePayload := pm.selectFakeTLSPayload(strat, rep, isClientHello, packet, ipHdrLen)
			fakePkts, err := pm.ApplyFake(packet, strat.FakeTTL, strat.Fooling, strat.BadSeqIncrement, fakePayload)
			if err != nil {
				pm.stats.Errors.Add(1)
				continue
			}
			packets = append(packets, fakePkts...)
			pm.stats.FakeCount.Add(uint64(len(fakePkts)))
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

	// HTTP modifiers (hostcase / extra-space / dot-at-end)
	isHTTPFlow := false
	if flow != nil {
		flow.Mu.RLock()
		isHTTPFlow = flow.IsHTTP
		flow.Mu.RUnlock()
	}

	if isHTTPFlow && strat.ApplyToHTTP && !isClientHello {
		httpPayload := applyHTTPMods(packet[payloadOffset:], strat)
		if httpPayload != nil {
			httpPkt, err := rebuildPacketWithPayload(packet, ipHdrLen, tcpHdrLen, httpPayload)
			if err != nil {
				pm.stats.Errors.Add(1)
				return &ModifyResult{SendOriginal: true}, nil
			}

			// Для HTTP-стратегий тоже применяем обычный TCP split по payload,
			// если он задан в профиле (light / medium и т.д.).
			if strat.SplitMode != strategy.SplitNone && len(strat.SplitPositions) > 0 {
				splitPkts, err := pm.ApplySplit(httpPkt, strat.SplitPositions, false)
				if err != nil {
					pm.stats.Errors.Add(1)
				} else if len(splitPkts) > 1 {
					packets = append(packets, splitPkts...)
					pm.stats.SplitCount.Add(uint64(len(splitPkts)))
					originalReplaced = true
					goto finalize
				}
			}

			packets = append(packets, httpPkt)
			originalReplaced = true
			goto finalize
		}
	}

	if isHTTPFlow && strat.FakeHTTPFileData != nil {
		for rep := 0; rep < fakeRepeats; rep++ {
			fakePkts, err := pm.ApplyFake(
				packet,
				strat.FakeTTL,
				strat.Fooling,
				strat.BadSeqIncrement,
				strat.FakeHTTPFileData,
			)
			if err != nil {
				pm.stats.Errors.Add(1)
				continue
			}
			packets = append(packets, fakePkts...)
			pm.stats.FakeCount.Add(uint64(len(fakePkts)))
		}

		// HTTP fake-пакеты — это decoy, оригинал должен уйти отдельно.
		if len(packets) > 0 {
			originalReplaced = false
			goto finalize
		}
	}

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
		if err != nil {
			pm.stats.Errors.Add(1)
		}
		if err == nil && len(seqPkts) > 0 {
			packets = append(packets, seqPkts...)
			pm.stats.SplitCount.Add(uint64(len(seqPkts)))
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
		if err != nil {
			pm.stats.Errors.Add(1)
		}
		if err == nil && len(fsPkts) > 0 {
			// FakedSplit уже включает fake-пакеты, не дублируем из шага 2
			// Заменяем packets (fake из шага 2 уже внутри ApplyFakedSplit)
			packets = fsPkts
			pm.stats.SplitCount.Add(uint64(len(fsPkts)))

			// Если payload > 1, ApplyFakedSplit гарантированно вернула реальные сегменты.
			// Иначе это fake-only режим, и оригинал должен уйти отдельно.
			originalReplaced = payloadLen > 1
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
		if err != nil {
			pm.stats.Errors.Add(1)
		}
		if err == nil && len(dPkts) > 0 {
			packets = append(packets, dPkts...)
			pm.stats.DisorderCount.Add(uint64(len(dPkts)))
			originalReplaced = true // dPkts содержит реальные сегменты после decoy
			goto finalize
		}
	}

	// 7. HostFakeSplit (HTTP)
	if strat.HostFakeSplit && flow != nil && flow.IsHTTP {
		hfPkts, err := pm.ApplyHostFakeSplit(packet, strat)
		if err != nil {
			pm.stats.Errors.Add(1)
		}
		if err == nil && len(hfPkts) > 0 {
			packets = append(packets, hfPkts...)
			pm.stats.SplitCount.Add(uint64(len(hfPkts)))

			// HostFakeSplit здесь даёт только fake-пакеты.
			// Оригинал должен уйти отдельно обычным Send().
			originalReplaced = false
			goto finalize
		}
	}

	// 8. Split обычный
	if strat.SplitMode != strategy.SplitNone && len(strat.SplitPositions) > 0 && isClientHello {
		splitPkts, err := pm.ApplySplit(packet, strat.SplitPositions, strat.SplitSNIOffset)
		if err == nil && len(splitPkts) > 1 {
			packets = append(packets, splitPkts...)
			pm.stats.SplitCount.Add(uint64(len(splitPkts)))
			originalReplaced = true
			goto finalize
		}
		if err != nil {
			pm.stats.Errors.Add(1)
		}
	}

	// 9. TLS record split — последний резерв
	if strat.TLSRecordSplit && protocol.IsTLS(packet[payloadOffset:]) {
		tlsFrag, err := pm.ApplyTLSSplit(packet[payloadOffset:], strat.TLSRecordSize)
		if err != nil {
			pm.stats.Errors.Add(1)
		}
		if err == nil && len(tlsFrag) > 1 {
			seq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
			addedTLS := 0

			for _, frag := range tlsFrag {
				newPkt := make([]byte, ipHdrLen+tcpHdrLen+len(frag))
				copy(newPkt, packet[:payloadOffset])
				binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
				binary.BigEndian.PutUint32(newPkt[ipHdrLen+4:], seq)
				copy(newPkt[payloadOffset:], frag)

				if err := fixPacketChecksums(newPkt); err != nil {
					pm.stats.Errors.Add(1)
					continue
				}

				packets = append(packets, newPkt)
				addedTLS++
				seq += uint32(len(frag))
			}

			if addedTLS > 0 {
				originalReplaced = true
			}
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

	pm.stats.PacketsModified.Add(uint64(len(packets)))
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

func rebuildPacketWithPayload(packet []byte, ipHdrLen, tcpHdrLen int, payload []byte) ([]byte, error) {
	payloadOffset := ipHdrLen + tcpHdrLen

	newPkt := make([]byte, payloadOffset+len(payload))
	copy(newPkt, packet[:payloadOffset])
	copy(newPkt[payloadOffset:], payload)

	binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
	if err := fixPacketChecksums(newPkt); err != nil {
		return nil, err
	}
	return newPkt, nil
}

func fixPacketChecksums(packet []byte) error {
	recalculateIPChecksum(packet)
	return FixTCPChecksum(packet)
}

func isHTTPRequestPayload(payload []byte) bool {
	switch {
	case bytes.HasPrefix(payload, []byte("GET ")),
		bytes.HasPrefix(payload, []byte("POST ")),
		bytes.HasPrefix(payload, []byte("HEAD ")),
		bytes.HasPrefix(payload, []byte("PUT ")),
		bytes.HasPrefix(payload, []byte("DELETE ")),
		bytes.HasPrefix(payload, []byte("OPTIONS ")),
		bytes.HasPrefix(payload, []byte("PATCH ")),
		bytes.HasPrefix(payload, []byte("CONNECT ")),
		bytes.HasPrefix(payload, []byte("TRACE ")):
		return true
	default:
		return false
	}
}

func applyHTTPMods(payload []byte, strat *strategy.Strategy) []byte {
	hostCase := strat.HostCase ||
		strat.HTTPModMode == strategy.HTTPModHostCase ||
		strat.HTTPModMode == strategy.HTTPModAll

	extraSpace := strat.ExtraSpace ||
		strat.HTTPModMode == strategy.HTTPModExtraSpace ||
		strat.HTTPModMode == strategy.HTTPModAll

	dotAtEnd := strat.DotAtEnd ||
		strat.HTTPModMode == strategy.HTTPModDotAtEnd ||
		strat.HTTPModMode == strategy.HTTPModAll

	if !hostCase && !extraSpace && !dotAtEnd {
		return nil
	}
	if !isHTTPRequestPayload(payload) {
		return nil
	}

	out := append([]byte(nil), payload...)
	changed := false

	// extra-space: "GET /" -> "GET  /"
	if extraSpace {
		if sp := bytes.IndexByte(out, ' '); sp > 0 {
			if sp+1 < len(out) && out[sp+1] != ' ' {
				tmp := make([]byte, 0, len(out)+1)
				tmp = append(tmp, out[:sp+1]...)
				tmp = append(tmp, ' ')
				tmp = append(tmp, out[sp+1:]...)
				out = tmp
				changed = true
			}
		}
	}

	lower := bytes.ToLower(out)

	hostIdx := bytes.Index(lower, []byte("\r\nhost:"))
	if hostIdx >= 0 {
		hostIdx += 2 // пропускаем \r\n
	} else if bytes.HasPrefix(lower, []byte("host:")) {
		hostIdx = 0
	}

	if hostIdx >= 0 {
		lineEnd := hostIdx
		for lineEnd < len(out) && out[lineEnd] != '\r' && out[lineEnd] != '\n' {
			lineEnd++
		}

		line := out[hostIdx:lineEnd]
		colon := bytes.IndexByte(line, ':')
		if colon > 0 {
			valueStart := hostIdx + colon + 1
			for valueStart < lineEnd && out[valueStart] == ' ' {
				valueStart++
			}

			hostValue := append([]byte(nil), out[valueStart:lineEnd]...)

			if dotAtEnd && (len(hostValue) == 0 || hostValue[len(hostValue)-1] != '.') {
				hostValue = append(hostValue, '.')
				changed = true
			}

			headerName := []byte("Host")
			if hostCase {
				headerName = []byte("hOSt")
				changed = true
			}

			newLine := make([]byte, 0, len(headerName)+2+len(hostValue))
			newLine = append(newLine, headerName...)
			newLine = append(newLine, ':', ' ')
			newLine = append(newLine, hostValue...)

			if !bytes.Equal(out[hostIdx:lineEnd], newLine) {
				tmp := make([]byte, 0, len(out)-len(out[hostIdx:lineEnd])+len(newLine))
				tmp = append(tmp, out[:hostIdx]...)
				tmp = append(tmp, newLine...)
				tmp = append(tmp, out[lineEnd:]...)
				out = tmp
				changed = true
			}
		}
	}

	if !changed {
		return nil
	}
	return out
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
		return []byte{
			0x16, 0x03, 0x01, 0x00, 0x05,
			0x01, 0x00, 0x00, 0x01, 0x00,
		}
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

	return nil
}

// ApplyHostFakeSplit применяет hostfakesplit для HTTP трафика:
// заменяет Host: заголовок на strat.HostFakeSplitHost и разбивает поток там.
func (pm *PacketModifier) ApplyHostFakeSplit(packet []byte, strat *strategy.Strategy) ([][]byte, error) {
	if !strat.HostFakeSplit || strat.HostFakeSplitHost == "" {
		return nil, fmt.Errorf("hostfakesplit not configured")
	}

	_, _, payloadOffset, err := parseIPv4TCP(packet)
	if err != nil {
		return nil, err
	}
	if payloadOffset >= len(packet) {
		return nil, fmt.Errorf("no payload")
	}

	payload := packet[payloadOffset:]

	// Создаём fake-пакет с подменённым Host:
	fakePayload := replaceHTTPHost(payload, strat.HostFakeSplitHost)
	if fakePayload == nil {
		return nil, fmt.Errorf("host header not found")
	}

	return pm.ApplyFake(packet, strat.FakeTTL, strat.Fooling, strat.BadSeqIncrement, fakePayload)
}

// modifyClientHelloSNI заменяет SNI в TLS ClientHello.
//
// Стратегия: ищем позицию SNI через protocol.FindSNI, затем заменяем
// содержимое name in-place (если длина совпадает) или перестраиваем пакет
// (если новый SNI короче/длиннее — обновляем все вложенные length-поля).
//
// Возвращает nil если payload не является TLS ClientHello или SNI не найден.
func modifyClientHelloSNI(payload []byte, newSNI string) []byte {
	if len(payload) < 9 || payload[0] != 0x16 || payload[1] != 0x03 {
		return nil
	}

	sniPos, err := protocol.FindSNI(payload)
	if err != nil {
		return nil
	}

	// sniPos указывает на первый байт имени SNI (после nameType и nameLen).
	// Читаем текущую длину имени из двух байт перед sniPos.
	if sniPos < 5 || sniPos+0 > len(payload) {
		return nil
	}
	// nameLen находится в payload[sniPos-2 : sniPos]
	oldNameLen := int(binary.BigEndian.Uint16(payload[sniPos-2 : sniPos]))
	if sniPos+oldNameLen > len(payload) {
		return nil
	}

	newSNIBytes := []byte(newSNI)
	newNameLen := len(newSNIBytes)
	delta := newNameLen - oldNameLen

	// Строим новый payload:
	//   payload[:sniPos-2]              — всё до nameLen
	//   newNameLen (2 bytes BE)         — обновлённая длина имени
	//   newSNIBytes                     — новое имя
	//   payload[sniPos+oldNameLen:]     — остаток
	result := make([]byte, len(payload)+delta)
	copy(result, payload[:sniPos-2])
	binary.BigEndian.PutUint16(result[sniPos-2:], uint16(newNameLen))
	copy(result[sniPos:], newSNIBytes)
	copy(result[sniPos+newNameLen:], payload[sniPos+oldNameLen:])

	if delta == 0 {
		// Длина не изменилась — length-поля выше не нужно трогать
		return result
	}

	// Обновляем все вложенные length-поля которые охватывают SNI:
	//
	// Структура TLS ClientHello (смещения от начала payload):
	//   [0]     ContentType (1)
	//   [1:3]   RecordVersion (2)
	//   [3:5]   RecordLength (2)          ← обновить
	//   [5]     HandshakeType (1)
	//   [6:9]   HandshakeLength (3)       ← обновить
	//   ...extensions...
	//     ExtType(2) + ExtLen(2)          ← обновить SNI extension length
	//       SNI list length (2)           ← обновить
	//         nameType(1) + nameLen(2)    ← уже обновлено выше
	//
	// TLS record length: bytes [3:5]
	if len(result) >= 5 {
		oldRecordLen := int(binary.BigEndian.Uint16(result[3:5]))
		binary.BigEndian.PutUint16(result[3:5], uint16(oldRecordLen+delta))
	}

	// Handshake length: 3-byte BE at bytes [6:9]
	if len(result) >= 9 {
		oldHsLen := int(result[6])<<16 | int(result[7])<<8 | int(result[8])
		newHsLen := oldHsLen + delta
		result[6] = byte(newHsLen >> 16)
		result[7] = byte(newHsLen >> 8)
		result[8] = byte(newHsLen)
	}

	// Ищем SNI extension (type=0x0000) чтобы обновить его ExtLen и SNI list length.
	// Парсим extension list заново из result (после изменения длин выше).
	updateSNIExtensionLengths(result, sniPos, delta)

	return result
}

// updateSNIExtensionLengths обновляет ExtLen и SNI list length в уже модифицированном
// ClientHello. sniPos — позиция первого байта имени SNI (после nameLen).
func updateSNIExtensionLengths(data []byte, sniPos int, delta int) {
	// Пропускаем record header(5) + handshake header(4) + version(2) + random(32)
	pos := 5 + 4 + 2 + 32
	if pos >= len(data) {
		return
	}
	// session ID
	sessionLen := int(data[pos])
	pos += 1 + sessionLen
	// cipher suites
	if pos+2 > len(data) {
		return
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen
	// compression methods
	if pos >= len(data) {
		return
	}
	compLen := int(data[pos])
	pos += 1 + compLen
	// extensions length field
	if pos+2 > len(data) {
		return
	}
	extTotalLenOff := pos
	extTotalLen := int(binary.BigEndian.Uint16(data[pos:]))
	binary.BigEndian.PutUint16(data[extTotalLenOff:], uint16(extTotalLen+delta))
	pos += 2

	end := pos + extTotalLen + delta
	if end > len(data) {
		end = len(data)
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if extType == 0x0000 { // server_name extension
			// Обновляем ExtLen
			binary.BigEndian.PutUint16(data[pos+2:pos+4], uint16(extLen+delta))
			// Обновляем SNI list length (2 bytes после pos+4)
			if pos+6 <= len(data) {
				listLen := int(binary.BigEndian.Uint16(data[pos+4 : pos+6]))
				binary.BigEndian.PutUint16(data[pos+4:pos+6], uint16(listLen+delta))
			}
			return
		}
		pos += 4 + extLen
	}
}

// replaceHTTPHost заменяет Host: заголовок в HTTP payload.
// Поиск регистронезависимый через bytes.ToLower (#6 в review).
func replaceHTTPHost(payload []byte, newHost string) []byte {
	lower := bytes.ToLower(payload)

	hostIdx := bytes.Index(lower, []byte("\r\nhost:"))
	if hostIdx >= 0 {
		hostIdx += 2
	} else if bytes.HasPrefix(lower, []byte("host:")) {
		hostIdx = 0
	} else {
		return nil
	}

	lineEnd := hostIdx
	for lineEnd < len(payload) && payload[lineEnd] != '\r' && payload[lineEnd] != '\n' {
		lineEnd++
	}

	line := payload[hostIdx:lineEnd]
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return nil
	}

	newLine := []byte("Host: " + newHost)

	result := make([]byte, 0, len(payload)-len(line)+len(newLine))
	result = append(result, payload[:hostIdx]...)
	result = append(result, newLine...)
	result = append(result, payload[lineEnd:]...)
	return result
}

func parseIPv4TCP(packet []byte) (ipHdrLen, tcpHdrLen, payloadOffset int, err error) {
	if len(packet) < 40 {
		return 0, 0, 0, fmt.Errorf("packet too short: %d", len(packet))
	}
	if packet[0]>>4 != 4 {
		return 0, 0, 0, fmt.Errorf("not IPv4")
	}
	if packet[9] != 6 {
		return 0, 0, 0, fmt.Errorf("not TCP")
	}

	ipHdrLen = int(packet[0]&0x0F) * 4
	if ipHdrLen < 20 || ipHdrLen > 60 || len(packet) < ipHdrLen+20 {
		return 0, 0, 0, fmt.Errorf("invalid IPv4 header length: %d", ipHdrLen)
	}

	tcpHdrLen = int(packet[ipHdrLen+12]>>4) * 4
	if tcpHdrLen < 20 || tcpHdrLen > 60 {
		return 0, 0, 0, fmt.Errorf("invalid TCP header length: %d", tcpHdrLen)
	}

	payloadOffset = ipHdrLen + tcpHdrLen
	if payloadOffset > len(packet) {
		return 0, 0, 0, fmt.Errorf("payload offset out of range: %d > %d", payloadOffset, len(packet))
	}

	return ipHdrLen, tcpHdrLen, payloadOffset, nil
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
	p := packet[payloadOffset:]
	// Первые байты похожи на TLS record header
	if payloadLen < 5 {
		return false
	}

	// ContentType: Handshake (0x16)
	if p[0] != 0x16 || p[1] != 0x03 {
		return false
	}

	if payloadLen < 9 {
		return true
	}
	//if p[0] != 0x16 {
	//	return false
	//}
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

// GetStats возвращает иммутабельный снимок статистики.
func (pm *PacketModifier) GetStats() ModifierStatsSnapshot {
	return ModifierStatsSnapshot{
		PacketsProcessed: pm.stats.PacketsProcessed.Load(),
		PacketsModified:  pm.stats.PacketsModified.Load(),
		SplitCount:       pm.stats.SplitCount.Load(),
		DisorderCount:    pm.stats.DisorderCount.Load(),
		FakeCount:        pm.stats.FakeCount.Load(),
		Errors:           pm.stats.Errors.Load(),
	}
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
