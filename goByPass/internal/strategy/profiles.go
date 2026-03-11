package strategy

// loadDefaultStrategies загружает встроенные стратегии.
// Все стратегии используют новую систему: Fooling-битмаска вместо FakeMode,
// SeqOvl вместо SplitAfterSNI/SplitFirstByte, SynData/MultiDisorder вместо DisorderReverseFrag.
func (m *Manager) loadDefaultStrategies() {

	// ── 1. Passthrough ────────────────────────────────────────────────────────
	// Priority: 999999 — никогда не выбирается в fallback-цикле.
	// Используется только явно из pipeline как «ничего не делать».
	m.AddStrategy(&Strategy{
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
	m.AddStrategy(&Strategy{
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
	m.AddStrategy(&Strategy{
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
	m.AddStrategy(&Strategy{
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
	m.AddStrategy(&Strategy{
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
	// Аналог general.bat: multisplit seqovl=681 pos=1 (tls_clienthello_www_google_com.bin)
	m.AddStrategy(&Strategy{
		ID:          20,
		Name:        "youtube-2026",
		Description: "YouTube 2026: multisplit seqovl=681 + fake fooling=ts + disorder OOB",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		// multisplit (seqovl)
		SplitMode:         SplitSeqOvl,
		SplitPositions:    []int{1},
		SeqOvlLen:         681,
		SeqOvlPatternFile: "tls_clienthello_www_google_com.bin",

		// disorder
		DisorderMode: DisorderOutOfBand,
		DisorderPos:  []int{1},
		DisorderTTL:  1,

		// fake
		Fooling:     FoolingTS,
		FakeTTL:     6,
		FakeRepeats: 6,
		FakeTLSFiles: []string{
			"tls_clienthello_www_google_com.bin",
		},

		// QUIC
		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		ApplyToPacketTypes:     []string{"handshake", "ack"},
		Priority:               1,
		ModifyFirstDataPackets: 4,
	})

	// ── 21. Discord 2026 — split 1+5 + fake TS + TLS record split ─────────────
	m.AddStrategy(&Strategy{
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

	// ── 25. yt-discord-2026-zapret — multisplit seqovl=681 + fake + fooling=ts ──
	// Аналог general.bat (основной рабочий пресет):
	// multisplit seqovl=681 pos=1 fooling=ts repeats=6 tls=google+stun
	m.AddStrategy(&Strategy{
		ID:          25,
		Name:        "yt-discord-2026-zapret",
		Description: "TSPU 2026: multisplit seqovl=681 + fake fooling=ts x6 (аналог zapret general.bat)",
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		// multisplit seqovl
		SplitMode:         SplitSeqOvl,
		SplitPositions:    []int{1},
		SeqOvlLen:         681,
		SeqOvlPatternFile: "tls_clienthello_www_google_com.bin",

		// fake
		Fooling:     FoolingTS,
		FakeTTL:     6,
		FakeRepeats: 6,
		FakeTLSFiles: []string{
			"stun.bin",
			"tls_clienthello_www_google_com.bin",
		},
		FakeHTTPFile: "tls_clienthello_max_ru.bin",

		// QUIC
		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		Priority: 1,
	})

	// ── 60. syndata+multidisorder — агрессивный режим (ALT5) ─────────────────
	// NOT RECOMMENDED: не работает на некоторых провайдерах
	m.AddStrategy(&Strategy{
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
