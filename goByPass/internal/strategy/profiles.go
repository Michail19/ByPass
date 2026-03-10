package strategy

// LoadDefaultStrategies загружает стратегии по умолчанию
func (m *Manager) loadDefaultStrategies() {
	// Стратегия 1: Минимальная (только split)
	m.AddStrategy(&Strategy{
		ID:                     1,
		Name:                   "minimal",
		Description:            "Минимальная стратегия - только split первого байта",
		ApplyToTLS:             true,
		ApplyToHTTP:            true,
		SplitMode:              SplitFirstByte,
		SplitPositions:         []int{1},
		SplitSNIOffset:         true,
		Priority:               10,
		ModifyFirstDataPackets: 2, // Добавлено: модифицировать первые 2 data-пакета
	})
	// Стратегия 2: Умеренная (split + hostcase)
	m.AddStrategy(&Strategy{
		ID:                     2,
		Name:                   "moderate",
		Description:            "Умеренная стратегия - split + изменение регистра Host:",
		ApplyToTLS:             true,
		ApplyToHTTP:            true,
		SplitMode:              SplitAfterSNI,
		SplitPositions:         []int{5, 10},
		SplitSNIOffset:         true,
		HTTPModMode:            HTTPModHostCase,
		HostCase:               true,
		Priority:               20,
		ModifyFirstDataPackets: 3,
	})
	// ... (аналогично для остальных стратегий, добавляем ModifyFirstDataPackets = 2-4)
	// Стратегия 3: Агрессивная (split + disorder)
	m.AddStrategy(&Strategy{
		ID:                     3,
		Name:                   "aggressive",
		Description:            "Агрессивная стратегия - split + disorder с низким TTL",
		ApplyToTLS:             true,
		SplitMode:              SplitAfterSNI,
		SplitPositions:         []int{1, 5, 10},
		SplitSNIOffset:         true,
		DisorderMode:           DisorderTTLZero,
		DisorderPos:            []int{1},
		DisorderTTL:            1,
		DisorderRepeats:        1,
		Priority:               30,
		ModifyFirstDataPackets: 4,
	})
	// Оставшиеся стратегии аналогично, с добавлением ModifyFirstDataPackets
	// ...
	// Для YouTube
	m.AddStrategy(&Strategy{
		ID:                     20,
		Name:                   "youtube-2026",
		Description:            "Оптимизировано под YouTube 2026: multisplit + fake + disorder OOB",
		ApplyToTLS:             true,
		SplitMode:              SplitCustom,
		SplitPositions:         []int{1, 3, 5},
		SplitSNIOffset:         true,
		DisorderMode:           DisorderOutOfBand,
		DisorderPos:            []int{1},
		DisorderTTL:            1,
		FakeMode:               FakeMD5Sig,
		FakePos:                0,
		FakeTTL:                1,
		TLSRecordSplit:         false,
		ApplyToPacketTypes:     []string{"handshake", "ack"},
		Priority:               5,
		ModifyFirstDataPackets: 4,
	})

	m.AddStrategy(&Strategy{
		ID:              25,
		Name:            "yt-discord-2026",
		Description:     "2026 TSPU bypass from zapret/ByeDPI",
		ApplyToTLS:      true,
		ApplyToQUIC:     true,
		SplitMode:       SplitAfterSNI,
		SplitPositions:  []int{1, 3, 7, 43},
		SplitSNIOffset:  true,
		DisorderMode:    DisorderReverseFrag,
		DisorderPos:     []int{1, 3},
		DisorderTTL:     4,
		DisorderRepeats: 2,
		FakeMode:        FakeBadSum,
		FakePos:         0,
		FakeTTL:         4,
		FakeRepeats:     1,
		TLSRecordSplit:  true,
		TLSRecordSize:   80,
		Priority:        1,
		QUICttl:         4,
	})

	// Устанавливаем стратегию по умолчанию
	// m.defaultID = 2 // moderate
}
