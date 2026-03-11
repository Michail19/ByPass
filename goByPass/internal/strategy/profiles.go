package strategy

import "log"

// loadDefaultStrategies загружает встроенные стратегии.
// FIX #8: AddStrategy возвращает ошибку если ID уже занят.
// Используем mustAdd — паникует при дублировании ID (ошибка программиста, не рантайм).
func (m *Manager) loadDefaultStrategies() {

	mustAdd := func(s *Strategy) {
		if err := m.AddStrategy(s); err != nil {
			log.Panicf("[Profiles] Failed to add built-in strategy id=%d name=%q: %v", s.ID, s.Name, err)
		}
	}

	// ── 1. Passthrough ────────────────────────────────────────────────────────
	// Priority: 999999 — никогда не выбирается в fallback-цикле.
	mustAdd(&Strategy{
		ID:          1,
		Name:        "passthrough",
		Description: "Без модификаций (для тестов)",
		ApplyToHTTP: true,
		ApplyToTLS:  true,
		ApplyToQUIC: true,
		SplitMode:   SplitNone,
		Priority:    999999,
	})

	// ── 2. Light — split pos=1 + hostcase ─────────────────────────────────────
	mustAdd(&Strategy{
		ID:                     2,
		Name:                   "light",
		Description:            "Лёгкий: split 1 байт + hostcase",
		ApplyToHTTP:            true,
		ApplyToTLS:             true,
		SplitMode:              SplitCustom,
		SplitPositions:         []int{1},
		SplitSNIOffset:         true,
		HTTPModMode:            HTTPModHostCase,
		HostCase:               true,
		Priority:               10,
		ModifyFirstDataPackets: 2,
	})

	// ── 3. Medium — split 1+5 + fake TS ──────────────────────────────────────
	mustAdd(&Strategy{
		ID:                     3,
		Name:                   "medium",
		Description:            "Средний: split 1+5 + fake fooling=ts",
		ApplyToHTTP:            true,
		ApplyToTLS:             true,
		SplitMode:              SplitCustom,
		SplitPositions:         []int{1, 5},
		SplitSNIOffset:         true,
		Fooling:                FoolingTS,
		FakeTTL:                8,
		FakeRepeats:            1,
		HTTPModMode:            HTTPModHostCase,
		HostCase:               true,
		Priority:               20,
		ModifyFirstDataPackets: 3,
	})

	// ── 4. Hard — split + disorder OOB + fake TS ──────────────────────────────
	mustAdd(&Strategy{
		ID:                     4,
		Name:                   "hard",
		Description:            "Жёсткий: split + disorder OOB + fake fooling=ts",
		ApplyToHTTP:            true,
		ApplyToTLS:             true,
		SplitMode:              SplitCustom,
		SplitPositions:         []int{1, 3, 5},
		SplitSNIOffset:         true,
		DisorderMode:           DisorderOutOfBand,
		DisorderPos:            []int{1},
		DisorderTTL:            1,
		Fooling:                FoolingTS,
		FakeTTL:                1,
		FakeRepeats:            1,
		Priority:               30,
		ModifyFirstDataPackets: 4,
	})

	// ── 12. Telegram — split 1+5 + fake TS + TLS record split ─────────────────
	mustAdd(&Strategy{
		ID:                     12,
		Name:                   "telegram",
		Description:            "Telegram: split 1+5 + fake TS + TLS record split",
		ApplyToHTTP:            false,
		ApplyToTLS:             true,
		SplitMode:              SplitCustom,
		SplitPositions:         []int{1, 5},
		SplitSNIOffset:         true,
		Fooling:                FoolingTS,
		FakeTTL:                8,
		FakeRepeats:            1,
		HTTPModMode:            HTTPModHostCase,
		HostCase:               true,
		TLSRecordSplit:         true,
		TLSRecordSize:          128,
		Priority:               3,
		ModifyFirstDataPackets: 2,
	})

	// ── 20. YouTube 2026 — multisplit seqovl=681 + fake TS + disorder OOB ─────
	mustAdd(&Strategy{
		ID:          20,
		Name:        "youtube-2026",
		Description: "YouTube 2026: multisplit seqovl=681 + fake fooling=ts + disorder OOB",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		SplitMode:         SplitSeqOvl,
		SplitPositions:    []int{1},
		SeqOvlLen:         681,
		SeqOvlPatternFile: "tls_clienthello_www_google_com.bin",

		DisorderMode: DisorderOutOfBand,
		DisorderPos:  []int{1},
		DisorderTTL:  1,

		Fooling:     FoolingTS,
		FakeTTL:     6,
		FakeRepeats: 6,
		FakeTLSFiles: []string{
			"tls_clienthello_www_google_com.bin",
		},

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		ApplyToPacketTypes:     []string{"handshake", "ack"},
		Priority:               1,
		ModifyFirstDataPackets: 4,
	})

	// ── 21. Discord 2026 ───────────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:             21,
		Name:           "discord-2026",
		Description:    "Discord: split 1+5 + fake fooling=ts + TLS record split",
		ApplyToHTTP:    false,
		ApplyToTLS:     true,
		SplitMode:      SplitCustom,
		SplitPositions: []int{1, 5},
		SplitSNIOffset: true,
		Fooling:        FoolingTS,
		FakeTTL:        8,
		FakeRepeats:    6,
		FakeTLSFiles:   []string{"tls_clienthello_www_google_com.bin"},
		HTTPModMode:    HTTPModHostCase,
		HostCase:       true,
		TLSRecordSplit: true,
		TLSRecordSize:  128,
		Priority:       2,
	})

	// ── 25. yt-discord-2026-zapret — основной рабочий пресет 2026 ─────────────
	mustAdd(&Strategy{
		ID:          25,
		Name:        "yt-discord-2026-zapret",
		Description: "TSPU 2026: multisplit seqovl=681 + fake fooling=ts x6 (аналог zapret general.bat)",
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		SplitMode:         SplitSeqOvl,
		SplitPositions:    []int{1},
		SeqOvlLen:         681,
		SeqOvlPatternFile: "tls_clienthello_www_google_com.bin",

		Fooling:     FoolingTS,
		FakeTTL:     6,
		FakeRepeats: 6,
		FakeTLSFiles: []string{
			"stun.bin",
			"tls_clienthello_www_google_com.bin",
		},
		FakeHTTPFile: "tls_clienthello_max_ru.bin",

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		Priority: 1,
	})

	// ── 60. syndata+multidisorder — агрессивный режим ──────────────────────────
	mustAdd(&Strategy{
		ID:            60,
		Name:          "syndata-multidisorder",
		Description:   "syndata+multidisorder (агрессивный, НЕ РЕКОМЕНДУЕТСЯ — ALT5)",
		ApplyToHTTP:   true,
		ApplyToTLS:    true,
		SynData:       true,
		MultiDisorder: true,
		Priority:      60,
	})
}
