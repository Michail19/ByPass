package modifier

import (
	"ByPass/internal/cache"
	"ByPass/internal/conntrack"
	"ByPass/internal/protocol"
	"ByPass/internal/strategy"
	"bytes"
	"crypto/rand"
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
	// Меняем поле IP ID у исходного пакета, поэтому сразу чиним IPv4 checksum.
	// Иначе при SendOriginal=true наружу может уйти оригинальный пакет
	// с уже изменённым IP ID, но со старой checksum.
	//
	// TCP checksum трогать НЕ нужно:
	// pseudo-header включает src/dst/proto/len, но не включает IP ID.
	if strat.IPIDZero {
		packet[4] = 0
		packet[5] = 0
		recalculateIPChecksum(packet)
	}

	isClientHello := isClientHelloPacket(packet, payloadOffset, payloadLen)
	fakedSplitEnabled := strat.FakedSplit || strat.SplitMode == strategy.SplitFakedSplit
	multiDisorderEnabled := strat.MultiDisorder || strat.SplitMode == strategy.SplitMultiDisorder

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
		strat.FakeTLSModRnd ||
		strat.FakeTLSModDupSID ||
		strat.FakeTLSModSNI != ""

	fakeRepeats := strat.FakeRepeats
	if fakeRepeats <= 0 {
		fakeRepeats = 1
	}

	// ── 2. Fake ───────────────────────────────────────────────────────────────
	effectiveFooling := strat.Fooling
	if effectiveFooling == strategy.FoolingTS && !hasTCPTimestampOption(packet, ipHdrLen) {
		effectiveFooling = 0
	}

	if effectiveFooling != 0 && hasFooling && !fakedSplitEnabled && (isClientHello || strat.AnyProtocol) {
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
				splitPkts, err := pm.ApplySplit(httpPkt, strat.SplitPositions, false, strat.SplitPosMidSLD, strat.SplitPosSNIExt)
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
			strat.SplitSNIOffset, strat.SplitPosMidSLD, strat.SplitPosSNIExt,
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
	if fakedSplitEnabled && isClientHello {
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
	if multiDisorderEnabled || strat.DisorderMode != strategy.DisorderNone {
		disorderPos := strat.DisorderPos
		if len(disorderPos) == 0 {
			disorderPos = strat.SplitPositions
		}
		if len(disorderPos) == 0 {
			disorderPos = []int{1}
		}

		// NEW: поддержка позиций относительно SNI для disorder,
		// чтобы можно было выразить byedpi-подобные 1+s / 3+s.
		resolvedDisorderPos := disorderPos
		if strat.SplitSNIOffset || strat.SplitPosMidSLD || strat.SplitPosSNIExt {
			if rp, err := resolveSplitPositions(
				packet[payloadOffset:],
				disorderPos,
				strat.SplitSNIOffset,
				strat.SplitPosMidSLD,
				strat.SplitPosSNIExt,
			); err == nil && len(rp) > 0 {
				resolvedDisorderPos = rp
			}
		}

		dPkts, err := pm.ApplyDisorder(
			packet,
			resolvedDisorderPos,
			strat.DisorderTTL,
			strat.DisorderMode,
			strat.Fooling,
			strat.BadSeqIncrement,
		)
		if err != nil {
			pm.stats.Errors.Add(1)
		}
		if err == nil && len(dPkts) > 0 {
			packets = append(packets, dPkts...)
			pm.stats.DisorderCount.Add(uint64(len(dPkts)))
			originalReplaced = true
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

			// Если есть реальные сегменты, оригинал больше не нужен.
			originalReplaced = len(hfPkts) > 1
			goto finalize
		}
	}

	// 8. Split обычный
	if strat.SplitMode != strategy.SplitNone && len(strat.SplitPositions) > 0 && isClientHello {
		splitPkts, err := pm.ApplySplit(packet, strat.SplitPositions, strat.SplitSNIOffset, strat.SplitPosMidSLD, strat.SplitPosSNIExt)
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
		tlsSplitPos := strat.TLSRecordSize
		if strat.SplitSNIOffset {
			if sniPos, err := protocol.FindSNI(packet[payloadOffset:]); err == nil {
				tlsSplitPos = sniPos + strat.TLSRecordSize
			}
		}
		tlsFrag, err := pm.ApplyTLSSplit(packet[payloadOffset:], tlsSplitPos)

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

func hasTCPTimestampOption(packet []byte, ipHdrLen int) bool {
	if len(packet) < ipHdrLen+20 {
		return false
	}
	tcpHdrLen := int((packet[ipHdrLen+12] >> 4) * 4)
	if tcpHdrLen <= 20 || len(packet) < ipHdrLen+tcpHdrLen {
		return false
	}

	opts := packet[ipHdrLen+20 : ipHdrLen+tcpHdrLen]
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case 0:
			return false
		case 1:
			i++
			continue
		}
		if i+1 >= len(opts) {
			return false
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			return false
		}
		if kind == 8 && l == 10 {
			return true
		}
		i += l
	}
	return false
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
	tcpHdrLen := int(packet[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen
	if payloadOffset >= len(packet) {
		return nil
	}

	var payload []byte
	switch {
	case strat.FakeTLSNullBytes:
		payload = []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	case strat.FakeTLSPrevPacket:
		payload = append([]byte(nil), packet[payloadOffset:]...)
	case len(strat.FakeTLSFilesData) > 0:
		payload = append([]byte(nil), strat.FakeTLSData(repIdx)...)
	default:
		payload = append([]byte(nil), packet[payloadOffset:]...)
	}

	if !strat.FakeTLSModNone && (strat.FakeTLSModRnd || strat.FakeTLSModDupSID || strat.FakeTLSModSNI != "") {
		if modified := applyClientHelloMods(payload, strat); modified != nil {
			payload = modified
		}
	}

	// Если payload совпадает с оригинальным и модификации не нужны — пусть ApplyFake
	// просто клонирует исходный packet без лишней аллокации.
	if !strat.FakeTLSNullBytes &&
		!strat.FakeTLSPrevPacket &&
		len(strat.FakeTLSFilesData) == 0 &&
		!strat.FakeTLSModRnd &&
		!strat.FakeTLSModDupSID &&
		strat.FakeTLSModSNI == "" {
		return nil
	}

	if len(payload) == 0 && !isClientHello {
		return nil
	}
	return payload
}

func applyClientHelloMods(payload []byte, strat *strategy.Strategy) []byte {
	if len(payload) < 44 || payload[0] != 0x16 || payload[5] != 0x01 {
		return payload
	}

	out := append([]byte(nil), payload...)

	if strat.FakeTLSModRnd && len(out) >= 43 {
		_, _ = rand.Read(out[11:43])
	}

	if strat.FakeTLSModDupSID {
		if modified := rewriteClientHelloSessionID(out, buildDupSessionID(out)); modified != nil {
			out = modified
		}
	}

	if strat.FakeTLSModSNI != "" {
		if modified := modifyClientHelloSNI(out, strat.FakeTLSModSNI); modified != nil {
			out = modified
		}
	}

	return out
}

func buildDupSessionID(payload []byte) []byte {
	if len(payload) < 44 {
		return nil
	}
	sidLen := int(payload[43])
	if 44+sidLen > len(payload) {
		return nil
	}
	if sidLen == 0 {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf[:16])
		copy(buf[16:], buf[:16])
		return buf
	}
	orig := payload[44 : 44+sidLen]
	outLen := sidLen * 2
	if outLen > 32 {
		outLen = 32
	}
	out := make([]byte, outLen)
	for i := 0; i < outLen; i++ {
		out[i] = orig[i%sidLen]
	}
	return out
}

func rewriteClientHelloSessionID(payload []byte, newSID []byte) []byte {
	if len(payload) < 44 || len(newSID) > 32 {
		return nil
	}
	oldSIDLen := int(payload[43])
	oldStart := 44
	oldEnd := oldStart + oldSIDLen
	if oldEnd > len(payload) {
		return nil
	}
	delta := len(newSID) - oldSIDLen
	out := make([]byte, len(payload)+delta)
	copy(out, payload[:43])
	out[43] = byte(len(newSID))
	copy(out[44:], newSID)
	copy(out[44+len(newSID):], payload[oldEnd:])

	if len(out) >= 5 {
		recLen := int(binary.BigEndian.Uint16(out[3:5])) + delta
		if recLen >= 0 && recLen <= 0xFFFF {
			binary.BigEndian.PutUint16(out[3:5], uint16(recLen))
		}
	}
	if len(out) >= 9 {
		hsLen := int(out[6])<<16 | int(out[7])<<8 | int(out[8])
		hsLen += delta
		if hsLen >= 0 && hsLen <= 0xFFFFFF {
			out[6] = byte(hsLen >> 16)
			out[7] = byte(hsLen >> 8)
			out[8] = byte(hsLen)
		}
	}
	return out
}

// ApplyHostFakeSplit применяет hostfakesplit для HTTP трафика:
// заменяет Host: заголовок на strat.HostFakeSplitHost и разбивает поток там.
func (pm *PacketModifier) ApplyHostFakeSplit(packet []byte, strat *strategy.Strategy) ([][]byte, error) {
	if !strat.HostFakeSplit || strat.HostFakeSplitHost == "" {
		return nil, fmt.Errorf("hostfakesplit not configured")
	}

	ipHdrLen, tcpHdrLen, payloadOffset, err := parseIPv4TCP(packet)
	if err != nil {
		return nil, err
	}
	if payloadOffset >= len(packet) {
		return nil, fmt.Errorf("no payload")
	}

	payload := packet[payloadOffset:]

	// 1. Fake payload с подменённым Host
	fakePayload := replaceHTTPHost(payload, strat.HostFakeSplitHost)
	if fakePayload == nil {
		return nil, fmt.Errorf("host header not found")
	}

	fakePkts, err := pm.ApplyFake(packet, strat.FakeTTL, strat.Fooling, strat.BadSeqIncrement, fakePayload)
	if err != nil {
		return nil, err
	}

	// 2. Реальный split внутри Host value: "exa|mple.com"
	splitPos := findHTTPHostValueSplitPos(payload)
	if splitPos <= 0 || splitPos >= len(payload) {
		return fakePkts, nil
	}

	realSegs, err := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, []int{splitPos})
	if err != nil {
		return nil, err
	}

	out := make([][]byte, 0, len(fakePkts)+len(realSegs))
	if strat.HostFakeSplitAltOrder != 0 {
		out = append(out, realSegs...)
		out = append(out, fakePkts...)
	} else {
		out = append(out, fakePkts...)
		out = append(out, realSegs...)
	}
	return out, nil
}

func findHTTPHostValueSplitPos(payload []byte) int {
	lower := bytes.ToLower(payload)

	hostIdx := bytes.Index(lower, []byte("\r\nhost:"))
	if hostIdx >= 0 {
		hostIdx += 2
	} else if bytes.HasPrefix(lower, []byte("host:")) {
		hostIdx = 0
	} else {
		return 0
	}

	lineEnd := hostIdx
	for lineEnd < len(payload) && payload[lineEnd] != '\r' && payload[lineEnd] != '\n' {
		lineEnd++
	}

	colon := bytes.IndexByte(payload[hostIdx:lineEnd], ':')
	if colon < 0 {
		return 0
	}

	valueStart := hostIdx + colon + 1
	for valueStart < lineEnd && (payload[valueStart] == ' ' || payload[valueStart] == '\t') {
		valueStart++
	}
	if valueStart >= lineEnd {
		return 0
	}

	if valueStart+1 < lineEnd {
		return valueStart + 1
	}
	return valueStart
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

func toAlternatingCaseASCII(b []byte) []byte {
	out := append([]byte(nil), b...)
	upper := false
	for i := range out {
		c := out[i]
		if c >= 'a' && c <= 'z' {
			if upper {
				out[i] = c - ('a' - 'A')
			}
			upper = !upper
		} else if c >= 'A' && c <= 'Z' {
			if !upper {
				out[i] = c + ('a' - 'A')
			}
			upper = !upper
		}
	}
	return out
}

func replaceFirstMethodSpace(payload []byte, repl []byte) []byte {
	sp := bytes.IndexByte(payload, ' ')
	if sp <= 0 {
		return nil
	}
	out := make([]byte, 0, len(payload)-1+len(repl))
	out = append(out, payload[:sp]...)
	out = append(out, repl...)
	out = append(out, payload[sp+1:]...)
	return out
}
