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
		Description: "Telegram Windows/RU: split pos=1 + fake TS x1 (no SNI offset)",
		ApplyToHTTP: false,
		ApplyToTLS:  true,
		ApplyToQUIC: false,

		SplitMode:      SplitCustom,
		SplitPositions: []int{1},
		SplitSNIOffset: false,

		Fooling:     FoolingTS,
		FakeTTL:     6,
		FakeRepeats: 1,

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

	// ── 27. YouTube safe Windows TCP ─────────────────────────────────────────
	mustAdd(&Strategy{
		ID:          27,
		Name:        "yt-safe-2026",
		Description: "YouTube SAFE: seqovl + fake + QUIC fake (handshake-only)",
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
		ID:            60,
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
}
