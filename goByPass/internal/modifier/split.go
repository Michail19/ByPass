package modifier

import (
	"ByPass/internal/protocol"
	"encoding/binary"
	"errors"
	"log"
)

var (
	ErrSplitSNIOffsetUnsupported = errors.New("SplitSNIOffset/alignSNI is not implemented")

	// SeqOvl нельзя silently деградировать в "верни original packet":
	// иначе modifier сочтёт технику успешно применённой и на wire уйдёт
	// fake-only + original вместо настоящего seqovl/split.
	ErrSeqOvlInvalidLen   = errors.New("seqovl_len must be > 0")
	ErrSeqOvlPatternEmpty = errors.New("seqovl pattern data is empty")
	ErrSeqOvlNoPayload    = errors.New("seqovl requires TCP payload")
)

// ApplySplit применяет разбиение пакета на сегменты в указанных позициях.
// Позиции сортируются — неотсортированный список приводит к перекрытию сегментов.
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int, alignSNI bool) ([][]byte, error) {
	if len(splitPos) == 0 {
		return nil, nil
	}

	ipHdrLen, tcpHdrLen, payloadOffset, err := parseIPv4TCP(packet)
	if err != nil {
		return nil, err
	}

	payload := packet[payloadOffset:]
	validPos, err := resolveSplitPositions(payload, splitPos, alignSNI)
	if err != nil {
		return nil, err
	}
	if len(validPos) == 0 {
		return [][]byte{packet}, nil
	}

	return buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, validPos)
}

func resolveSplitPositions(payload []byte, splitPos []int, alignSNI bool) ([]int, error) {
	var validPos []int

	base := 0
	if alignSNI {
		sniPos, err := protocol.FindSNI(payload)
		if err != nil {
			return nil, err
		}
		base = sniPos
	}

	for _, pos := range splitPos {
		resolved := pos
		if alignSNI {
			resolved = base + pos
		}
		if resolved > 0 && resolved < len(payload) {
			validPos = append(validPos, resolved)
		}
	}

	if len(validPos) == 0 {
		return nil, nil
	}
	sortInts(validPos)
	return dedupInts(validPos), nil
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
	seqOvlTTL int,
) ([][]byte, error) {
	ipHdrLen, tcpHdrLen, payloadOffset, err := parseIPv4TCP(packet)
	if err != nil {
		return nil, err
	}

	if ovlLen <= 0 {
		return nil, ErrSeqOvlInvalidLen
	}
	if len(pattern) == 0 {
		return nil, ErrSeqOvlPatternEmpty
	}

	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return nil, ErrSeqOvlNoPayload
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
	binary.BigEndian.PutUint32(ovlPkt[ipHdrLen+4:], ovlSeq)
	copy(ovlPkt[payloadOffset:], ovlData)

	// DF сохраняется из оригинала.
	// ovl-пакет должен умереть до сервера, но дойти до DPI.
	setIPTTL(ovlPkt, seqOvlTTL)
	if err := fixPacketChecksums(ovlPkt); err != nil {
		return nil, err
	}
	results = append(results, ovlPkt)

	// 2. Реальные сегменты в прямом порядке
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

	realSegs, err := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, validPos)
	if err != nil {
		return nil, err
	}
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
	ipHdrLen, tcpHdrLen, payloadOffset, err := parseIPv4TCP(packet)
	if err != nil {
		return nil, err
	}

	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return nil, nil
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
	if err != nil {
		return nil, err
	}
	results = append(results, fakePkts...)

	// Если splitPos плохой, но payload длиннее 1 байта — делаем безопасный fallback на split=1.
	// Если payload совсем короткий — остаёмся в fake-only режиме, а оригинал отправит pipeline.
	if splitPos <= 0 || splitPos >= payloadLen {
		if payloadLen <= 1 {
			return results, nil
		}
		splitPos = 1
	}

	segs, err := buildTCPSegments(packet, ipHdrLen, tcpHdrLen, payloadOffset, []int{splitPos})
	if err != nil {
		return nil, err
	}
	results = append(results, segs...)

	return results, nil
}

// ApplySynData реализует syndata:
// отправить SYN-пакет с данными fake payload перед реальным SYN.
// DPI теряет начало потока и не успевает анализировать реальный handshake.
//
// Замечание (#5): SYN+data отклоняется некоторыми middlebox'ами (Cloudflare, корп. firewall).
// Включать только для провайдеров где это явно работает.
// ApplySynData реализует технику syndata (zapret ALT5):
// отправляет fake SYN с payload ДО реального SYN.
//
// Цель: DPI запоминает ISN = fakeSynSeq = realISN - len(fakeData).
// Когда приходит реальный ClientHello (с realISN+1), DPI не может правильно
// определить смещение внутри TLS-потока → не может разобрать ClientHello → bypass.
//
// ВАЖНО: fake SYN должен иметь TTL = disorderTTL (обычно 4):
//   - Fake SYN с TTL=128 ДОХОДИТ до сервера (6 hop'ов)
//   - Сервер отвечает SYN-ACK на fake ISN
//   - Windows видит неизвестный SYN-ACK → шлёт RST
//   - Сервер видит RST → закрывает все последующие соединения с этого IP
//   - Это убивает bypass полностью
//
// Правильный TTL: fake SYN умирает до сервера, DPI его видит (DPI ~2-3 hop).
func (pm *PacketModifier) ApplySynData(packet []byte, fakeData []byte, ttl int) ([][]byte, error) {
	ipHdrLen, tcpHdrLen, _, err := parseIPv4TCP(packet)
	if err != nil {
		return nil, err
	}

	flags := packet[ipHdrLen+13]
	isSYN := (flags & 0x02) != 0
	isACK := (flags & 0x10) != 0
	if !isSYN || isACK {
		return nil, nil
	}

	// Если fakeData не загружен из файла, генерируем синтетический payload.
	// zapret ALT5 использует --dpi-desync-fake-syndata или просто --dpi-desync=syndata
	// без явного файла — в этом случае zapret генерирует 1 байт \x00 (TLS alert).
	// Мы используем минимальный TLS-Alert (10 байт), который выглядит как валидный
	// TLS-пакет для DPI, но является мусором для сервера → сервер игнорирует SYN+data.
	if len(fakeData) == 0 {
		// Более мягкий fallback, ближе к поведению zapret:
		// минимальный 1-байтный payload вместо 10-байтного synthetic TLS alert.
		// Это уменьшает шанс, что middlebox / server path негативно отреагирует
		// именно на SYN+10B payload.
		fakeData = []byte{0x00}
	}

	// TTL sanity: если 0 или не задан, используем zapret default
	if ttl <= 0 {
		ttl = 4
	}

	originalSeq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
	// Fake SYN seq: originalSeq - len(fakeData).
	// DPI запоминает ISN = fakeSynSeq. Когда приходит реальный CH (с ISN+1 = fakeSynSeq+len+1),
	// DPI ищет TLS-запись с неправильным смещением → не может разобрать SNI → bypass.
	synDataSeq := originalSeq - uint32(len(fakeData))

	synPkt := make([]byte, ipHdrLen+tcpHdrLen+len(fakeData))
	copy(synPkt, packet[:ipHdrLen+tcpHdrLen])
	binary.BigEndian.PutUint16(synPkt[2:4], uint16(len(synPkt)))
	binary.BigEndian.PutUint32(synPkt[ipHdrLen+4:], synDataSeq)
	synPkt[ipHdrLen+13] = flags & 0x02
	copy(synPkt[ipHdrLen+tcpHdrLen:], fakeData)

	// КРИТИЧНО: устанавливаем низкий TTL на fake SYN
	// Fake SYN должен умереть до сервера (DPI ~2-3 hop, сервер ~6 hop → TTL=4 оптимально)
	setIPTTL(synPkt, ttl)
	if err := fixPacketChecksums(synPkt); err != nil {
		return nil, err
	}

	return [][]byte{synPkt}, nil
}

// buildTCPSegments разбивает packet на TCP-сегменты по validPos (уже отсортированным).
// Если validPos пуст — возвращает packet как есть.
// DF flag: копируется из оригинального packet[6] через copy(newPkt, packet[:payloadOffset]).
func buildTCPSegments(packet []byte, ipHdrLen, tcpHdrLen, payloadOffset int, validPos []int) ([][]byte, error) {
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return [][]byte{packet}, nil
	}

	var chunks [][]byte
	prev := 0
	for _, pos := range validPos {
		chunks = append(chunks, packet[payloadOffset+prev:payloadOffset+pos])
		prev = pos
	}
	chunks = append(chunks, packet[payloadOffset+prev:])

	seq := binary.BigEndian.Uint32(packet[ipHdrLen+4:])
	results := make([][]byte, 0, len(chunks))

	for i, seg := range chunks {
		newPkt := make([]byte, payloadOffset+len(seg))
		copy(newPkt, packet[:payloadOffset])

		flags := packet[ipHdrLen+13]
		if i != len(chunks)-1 {
			flags &^= 0x01 // FIN
			flags &^= 0x08 // PSH
		}
		newPkt[ipHdrLen+13] = flags

		binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
		binary.BigEndian.PutUint32(newPkt[ipHdrLen+4:], seq)

		copy(newPkt[payloadOffset:], seg)

		if err := fixPacketChecksums(newPkt); err != nil {
			return nil, err
		}

		results = append(results, newPkt)
		seq += uint32(len(seg))
	}

	return results, nil
}

// SplitAtPosition разбивает пакет в указанной позиции
func SplitAtPosition(packet []byte, pos int) [][]byte {
	if pos <= 0 || pos >= len(packet) {
		return [][]byte{packet}
	}
	return [][]byte{packet[:pos], packet[pos:]}
}
