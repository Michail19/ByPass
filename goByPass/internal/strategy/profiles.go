package strategy

import "log"

// loadDefaultStrategies загружает встроенные стратегии.
func (m *Manager) loadDefaultStrategies() {
	mustAdd := func(s *Strategy) {
		if err := m.AddStrategy(s); err != nil {
			log.Panicf("[Profiles] Failed to add built-in strategy id=%d name=%q: %v", s.ID, s.Name, err)
		}
	}

	// ── 1. Passthrough ────────────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          1,
		Name:        "passthrough",
		Description: "Без модификаций (default direct mode)",
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
		SplitSNIOffset:         false,
		HTTPModMode:            HTTPModHostCase,
		HostCase:               true,
		Priority:               10,
		ModifyFirstDataPackets: 1,
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
		SplitSNIOffset:         false,
		Fooling:                FoolingTS,
		FakeTTL:                6,
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
		SplitSNIOffset:         false, // важно: не оставлять true, пока align-SNI не реализован нормально
		DisorderMode:           DisorderOutOfBand,
		DisorderPos:            []int{1},
		DisorderTTL:            4,
		Fooling:                FoolingTS,
		FakeTTL:                4,
		FakeRepeats:            1,
		Priority:               30,
		ModifyFirstDataPackets: 4,
	})

	// ── 12. Telegram ──────────────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          12,
		Name:        "telegram",
		Description: "Telegram safer TCP: split pos=1 only, handshake-only",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: false,

		SplitMode:      SplitCustom,
		SplitPositions: []int{1},
		SplitSNIOffset: false,

		TLSRecordSplit: false,
		TLSRecordSize:  0,

		ApplyToPacketTypes:     []string{"handshake"},
		Priority:               18,
		ModifyFirstDataPackets: 0,
	})

	// ── 20. YouTube safe-first Windows ────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          20,
		Name:        "youtube-2026",
		Description: "YouTube Windows safe-first: seqovl + fake TS x6 + QUIC fake",
		ApplyToHTTP: false,
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
			"tls_clienthello_www_google_com.bin",
		},

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		TLSRecordSplit: false,
		TLSRecordSize:  0,

		ApplyToPacketTypes:     []string{"handshake"},
		Priority:               35,
		ModifyFirstDataPackets: 0,
	})

	// ── 21. Discord ───────────────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          21,
		Name:        "discord-2026",
		Description: "Discord: seqovl + fake TS x6 + QUIC fake (zapret-like)",
		ApplyToHTTP: false,
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

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		ApplyToPacketTypes:     []string{"handshake"},
		Priority:               25,
		ModifyFirstDataPackets: 1,
	})

	// ── 25. General zapret analog ─────────────────────────────────────────────
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

		Priority:               25,
		ModifyFirstDataPackets: 4,
	})

	// ── 26. YouTube ALT5 ──────────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          26,
		Name:        "yt-syndata-2026",
		Description: "YouTube 2026 ALT5: syndata+multidisorder TCP + QUIC fake",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		SynData:       true,
		MultiDisorder: true,
		DisorderTTL:   4,

		// Усиливаем multidisorder: несколько позиций как в ALT5-подобных профилях,
		// и ограничиваем только handshake, чтобы не трогать лишний appdata.
		DisorderPos:        []int{1, 2, 3, 4, 5},
		ApplyToPacketTypes: []string{"handshake"},

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,
		FakeTTL:         6,

		// держим выше medium/light, чтобы не лезла в обычный fallback
		// и использовалась в основном через HostnameRules для YouTube
		Priority:               40,
		ModifyFirstDataPackets: 1,
	})

	// ── 60. YouTube fake-only main/web ───────────────────────────────────────
	mustAdd(&Strategy{
		ID:          160,
		Name:        "yt-fake-only-2026",
		Description: "YouTube main/web: fake TLS only + QUIC fake, no real TCP split",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		Fooling:     FoolingTS,
		FakeTTL:     6,
		FakeRepeats: 6,
		FakeTLSFiles: []string{
			"tls_clienthello_www_google_com.bin",
		},

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		ApplyToPacketTypes:     []string{"handshake"},
		Priority:               34,
		ModifyFirstDataPackets: 0,
	})

	mustAdd(&Strategy{
		ID:          60,
		Name:        "yt-seqovl-only-681",
		Description: "YouTube TCP: seqovl only, no fake",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: false,

		SplitMode:         SplitSeqOvl,
		SplitPositions:    []int{1},
		SeqOvlLen:         681,
		SeqOvlPatternFile: "tls_clienthello_www_google_com.bin",

		// чтобы overlap-пакет умер раньше
		DisorderTTL: 3,

		ApplyToPacketTypes:     []string{"handshake"},
		Priority:               34,
		ModifyFirstDataPackets: 0,
	})

	// ── 27. YouTube safe Windows TCP ─────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          27,
		Name:        "yt-safe-2026",
		Description: "YouTube conservative TCP: split pos=1 only; QUIC fake kept",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		SplitMode:      SplitCustom,
		SplitPositions: []int{1},
		SplitSNIOffset: false,

		TLSRecordSplit: false,
		TLSRecordSize:  0,

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		ApplyToPacketTypes:     []string{"handshake"},
		Priority:               35,
		ModifyFirstDataPackets: 0,
	})

	// ── 30. QUIC fake x6 ──────────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          30,
		Name:        "quic-fake-6",
		Description: "QUIC fake: 6 повторов quic_initial (ALT1-11 / SIMPLE / ALT5 UDP-ветка)",
		ApplyToQUIC: true,

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,

		Priority: 10,
	})

	mustAdd(&Strategy{
		ID:          31,
		Name:        "yt-alt5-tcp",
		Description: "YouTube ALT5-like: syndata + multidisorder TCP, QUIC fake",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		SynData:       true,
		MultiDisorder: true,
		DisorderTTL:   4,
		DisorderPos:   []int{1, 2, 3, 4, 5},

		FakeQUICFile:    "quic_initial_www_google_com.bin",
		FakeQUICRepeats: 6,
		FakeTTL:         6,

		ApplyToPacketTypes:     []string{"handshake"},
		Priority:               36,
		ModifyFirstDataPackets: 0,
	})

	// ── 35. Game UDP fake x14 ────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          35,
		Name:        "game-udp-fake-14",
		Description: "Game UDP: fake-unknown-udp x14, cutoff=n3 (ALT5)",
		ApplyToQUIC: false,
		AnyProtocol: true,

		FakeUnknownUDPFile: "quic_initial_www_google_com.bin",
		FakeRepeats:        14,
		Cutoff:             3,

		Priority: 22,
	})

	// ── 60. General TCP ALT5 ──────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:            601,
		Name:          "syndata-multidisorder",
		Description:   "TCP ALT5: syndata+multidisorder",
		ApplyToHTTP:   true,
		ApplyToTLS:    true,
		SynData:       true,
		MultiDisorder: true,
		DisorderTTL:   4,
		Priority:      60,
	})

	// ── 61. Game TCP ALT5 ─────────────────────────────────────────────────────
	mustAdd(&Strategy{
		ID:                     61,
		Name:                   "syndata-multidisorder-anyprot",
		Description:            "Game TCP ALT5: syndata+multidisorder + any-protocol + cutoff=4",
		ApplyToHTTP:            false,
		ApplyToTLS:             false,
		AnyProtocol:            true,
		SynData:                true,
		MultiDisorder:          true,
		DisorderTTL:            4,
		ModifyFirstDataPackets: 4,
		Cutoff:                 4,
		Priority:               61,
	})

	mustAdd(&Strategy{
		ID:          112,
		Name:        "telegram-appdata-2026",
		Description: "Telegram: split first TLS packets + first appdata packets",
		ApplyToTLS:  true,
		ApplyToQUIC: false,
		AnyProtocol: true,

		SplitMode:      SplitCustom,
		SplitPositions: []int{1},
		SplitSNIOffset: false,

		ApplyToPacketTypes:     []string{"handshake", "data"},
		ModifyFirstDataPackets: 2,
		Cutoff:                 2,
		Priority:               17,
	})

	//mustAdd(&Strategy{
	//	ID:          212,
	//	Name:        "telegram-web-split-data",
	//	Description: "Telegram Web: split 1,midsld on handshake + split first appdata packets",
	//	ApplyToHTTP: false,
	//	ApplyToTLS:  true,
	//	ApplyToQUIC: false,
	//	AnyProtocol: true,
	//
	//	SplitMode:      SplitCustom,
	//	SplitPositions: []int{1},
	//	SplitPosMidSLD: true,
	//
	//	ApplyToPacketTypes:     []string{"handshake", "data"},
	//	ModifyFirstDataPackets: 4,
	//	Cutoff:                 4,
	//	Priority:               17,
	//})

	mustAdd(&Strategy{
		ID:          213,
		Name:        "telegram-web-fakedsplit-badseq",
		Description: "Telegram Web fallback: fakedsplit + badseq on first TLS/appdata packets",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: false,
		AnyProtocol: true,

		SplitMode:              SplitFakedSplit,
		FakedSplitPos:          1,
		FakedSplitPattern:      0x00,
		Fooling:                FoolingBadSeq,
		BadSeqIncrement:        0x80000000,
		FakeTTL:                64,
		FakeRepeats:            2,
		FakeTLSFiles:           []string{"tls_clienthello_www_google_com.bin"},
		ApplyToPacketTypes:     []string{"handshake", "data"},
		ModifyFirstDataPackets: 2,
		Cutoff:                 3,
		Priority:               18,
	})

	//mustAdd(&Strategy{
	//	ID:          221,
	//	Name:        "discord-web-badseq-midsld",
	//	Description: "Discord web/API: fake + seqovl(681) + split 1,midsld + QUIC fake",
	//	ApplyToHTTP: false,
	//	ApplyToTLS:  true,
	//	ApplyToQUIC: true,
	//
	//	SplitMode:         SplitSeqOvl,
	//	SplitPositions:    []int{1},
	//	SplitPosMidSLD:    true,
	//	SeqOvlLen:         681,
	//	SeqOvlPatternFile: "tls_clienthello_www_google_com.bin",
	//
	//	Fooling:         FoolingBadSeq,
	//	BadSeqIncrement: 0x80000000,
	//	FakeTTL:         64,
	//	FakeRepeats:     2,
	//	FakeTLSFiles: []string{
	//		"tls_clienthello_www_google_com.bin",
	//	},
	//
	//	DisorderTTL:        4,
	//	FakeQUICFile:       "quic_initial_www_google_com.bin",
	//	FakeQUICRepeats:    11,
	//	ApplyToPacketTypes: []string{"handshake"},
	//	Priority:           26,
	//})

	//mustAdd(&Strategy{
	//	ID:          222,
	//	Name:        "discord-udp-voice",
	//	Description: "Discord voice/STUN: fake unknown UDP x6",
	//	ApplyToHTTP: false,
	//	ApplyToTLS:  false,
	//	ApplyToQUIC: false,
	//	AnyProtocol: true,
	//
	//	FakeUnknownUDPFile: "quic_initial_www_google_com.bin",
	//	FakeRepeats:        6,
	//	Cutoff:             4,
	//	Priority:           27,
	//})

	mustAdd(&Strategy{
		ID:          223,
		Name:        "discord-fakedsplit-badseq",
		Description: "Discord fallback: fake + fakedsplit + badseq + QUIC fake",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: true,

		SplitMode:         SplitFakedSplit,
		FakedSplitPos:     1,
		FakedSplitPattern: 0x00,

		Fooling:         FoolingBadSeq,
		BadSeqIncrement: 0x80000000,
		FakeTTL:         64,
		FakeRepeats:     2,
		FakeTLSFiles: []string{
			"tls_clienthello_www_google_com.bin",
		},

		FakeQUICFile:       "quic_initial_www_google_com.bin",
		FakeQUICRepeats:    11,
		ApplyToPacketTypes: []string{"handshake"},
		Priority:           25,
	})
}
