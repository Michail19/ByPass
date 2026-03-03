package strategy

// SplitMode определяет способ разбиения пакетов
type SplitMode int

const (
	SplitNone SplitMode = iota
	SplitFirstByte
	SplitAfterSNI
	SplitCustom
)

// DisorderMode определяет способ нарушения порядка
type DisorderMode int

const (
	DisorderNone DisorderMode = iota
	DisorderTTLZero
	DisorderOutOfBand
)

// FakeMode определяет способ создания поддельных пакетов
type FakeMode int

const (
	FakeNone FakeMode = iota
	FakeMD5Sig
	FakeBadSeq
	FakeDataNoAck
)

// Strategy определяет набор параметров обхода
type Strategy struct {
	ID          int
	Name        string
	Description string

	// Параметры разбиения
	Split          SplitMode
	SplitPos       []int // позиции для разбиения
	SplitSNIOffset bool  // смещение относительно SNI

	// Параметры нарушения порядка
	Disorder    DisorderMode
	DisorderPos []int // позиции для disorder
	DisorderTTL int   // TTL для disorder-пакетов

	// Параметры поддельных пакетов
	Fake    FakeMode
	FakePos int // позиция для fake
	FakeTTL int // TTL для fake

	// Модификация HTTP
	HostCase   bool // изменение регистра Host:
	ExtraSpace bool // добавление пробела после метода
	DotAtEnd   bool // точка в конце Host:

	// TLS-специфичные параметры
	TLSRecordSplit bool // разделение TLS-записей
	TLSRecordSize  int  // размер TLS-записи

	// Прочее
	WindowSize int // изменение TCP window size
	IPID       int // изменение IP ID
	TTL        int // изменение TTL
	DupCount   int // количество дубликатов
	DupTTL     int // TTL для дубликатов
}

// Manager управляет стратегиями
type Manager struct {
	strategies map[int]*Strategy
	defaultID  int
}

// SelectStrategy выбирает стратегию для IP/хоста
func (m *Manager) SelectStrategy(ip, hostname string) *Strategy {
	// Здесь может быть логика автоподбора
	// или выбор на основе списков

	return m.strategies[m.defaultID]
}
