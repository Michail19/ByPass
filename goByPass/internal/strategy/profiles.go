package strategy

// LoadDefaultStrategies загружает стратегии по умолчанию
func (m *Manager) loadDefaultStrategies() {
	// Стратегия 1: Минимальная (только split)
	m.AddStrategy(&Strategy{
		ID:          1,
		Name:        "minimal",
		Description: "Минимальная стратегия - только split первого байта",
		ApplyToTLS:  true,
		ApplyToHTTP: true,

		SplitMode:      SplitFirstByte,
		SplitPositions: []int{1},
		SplitSNIOffset: true,

		Priority: 10,
	})

	// Стратегия 2: Умеренная (split + hostcase)
	m.AddStrategy(&Strategy{
		ID:          2,
		Name:        "moderate",
		Description: "Умеренная стратегия - split + изменение регистра Host:",
		ApplyToTLS:  true,
		ApplyToHTTP: true,

		SplitMode:      SplitAfterSNI,
		SplitPositions: []int{5, 10},
		SplitSNIOffset: true,

		HTTPModMode: HTTPModHostCase,
		HostCase:    true,

		Priority: 20,
	})

	// Стратегия 3: Агрессивная (split + disorder)
	m.AddStrategy(&Strategy{
		ID:          3,
		Name:        "aggressive",
		Description: "Агрессивная стратегия - split + disorder с низким TTL",
		ApplyToTLS:  true,

		SplitMode:      SplitAfterSNI,
		SplitPositions: []int{1, 5, 10},
		SplitSNIOffset: true,

		DisorderMode:    DisorderTTLZero,
		DisorderPos:     []int{1},
		DisorderTTL:     1,
		DisorderRepeats: 1,

		Priority: 30,
	})

	// Стратегия 4: С фейками (split + fake)
	m.AddStrategy(&Strategy{
		ID:          4,
		Name:        "fake",
		Description: "Стратегия с поддельными пакетами",
		ApplyToTLS:  true,

		SplitMode:      SplitAfterSNI,
		SplitPositions: []int{1},
		SplitSNIOffset: true,

		FakeMode:    FakeMD5Sig,
		FakePos:     0,
		FakeTTL:     8,
		FakeRepeats: 1,

		Priority: 40,
	})

	// Стратегия 5: TLS record splitting
	m.AddStrategy(&Strategy{
		ID:          5,
		Name:        "tls-split",
		Description: "Разделение TLS записей",
		ApplyToTLS:  true,

		TLSRecordSplit: true,
		TLSRecordSize:  64,

		Priority: 25,
	})

	// Стратегия 6: HTTP only
	m.AddStrategy(&Strategy{
		ID:          6,
		Name:        "http-only",
		Description: "Только для HTTP - изменение регистра и пробелы",
		ApplyToHTTP: true,

		HTTPModMode: HTTPModAll,
		HostCase:    true,
		ExtraSpace:  true,
		DotAtEnd:    true,

		Priority: 15,
	})

	// Стратегия 7: Комбинированная (все методы)
	m.AddStrategy(&Strategy{
		ID:          7,
		Name:        "full",
		Description: "Полная стратегия - все методы вместе",
		ApplyToTLS:  true,
		ApplyToHTTP: true,

		SplitMode:      SplitAfterSNI,
		SplitPositions: []int{1, 5, 10},
		SplitSNIOffset: true,

		DisorderMode:    DisorderTTLZero,
		DisorderPos:     []int{1},
		DisorderTTL:     1,
		DisorderRepeats: 2,

		FakeMode:    FakeMD5Sig,
		FakePos:     0,
		FakeTTL:     8,
		FakeRepeats: 1,

		HTTPModMode: HTTPModAll,
		HostCase:    true,
		ExtraSpace:  true,

		TLSRecordSplit: true,
		TLSRecordSize:  64,

		Priority: 50,
	})

	// Страница 8: Для YouTube
	// Стратегия специально для YouTube (ID 20)
	m.AddStrategy(&Strategy{
		ID:                 20,
		Name:               "youtube-2026",
		Description:        "Оптимизировано под YouTube 2026: multisplit + fake + disorder OOB",
		ApplyToTLS:         true,
		SplitMode:          SplitCustom,    // новый режим или используйте SplitAfterSNI
		SplitPositions:     []int{1, 3, 5}, // мелкий split
		SplitSNIOffset:     true,
		DisorderMode:       DisorderOutOfBand, // только OOB
		DisorderPos:        []int{1},
		DisorderTTL:        1,
		FakeMode:           FakeMD5Sig,
		FakePos:            0,
		FakeTTL:            1,     // очень низкий TTL
		TLSRecordSplit:     false, // отключить
		ApplyToPacketTypes: []string{"handshake", "ack"},
		Priority:           5, // самый высокий
	})

	// Страница 9: Для Discord
	m.AddStrategy(&Strategy{
		ID:          9,
		Name:        "discord",
		Description: "Оптимизировано для Discord",
		ApplyToTLS:  true,

		SplitMode:      SplitAfterSNI,
		SplitPositions: []int{1, 3},
		SplitSNIOffset: true,

		FakeMode: FakeMD5Sig,
		FakePos:  0,
		FakeTTL:  8,

		TLSRecordSplit: true,
		TLSRecordSize:  128,

		Priority: 5,
	})

	// Устанавливаем стратегию по умолчанию
	m.defaultID = 2 // moderate
}
