package strategy

import (
	"encoding/json"
	"fmt"
	"time"
)

// SplitMode определяет способ разбиения пакетов
type SplitMode int

const (
	SplitNone SplitMode = iota
	SplitFirstByte
	SplitAfterSNI
	SplitAfterHost
	SplitCustom
)

func (s SplitMode) String() string {
	switch s {
	case SplitNone:
		return "none"
	case SplitFirstByte:
		return "first-byte"
	case SplitAfterSNI:
		return "after-sni"
	case SplitAfterHost:
		return "after-host"
	case SplitCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// DisorderMode определяет способ нарушения порядка
type DisorderMode int

const (
	DisorderNone DisorderMode = iota
	DisorderTTLZero
	DisorderOutOfBand
	DisorderBadSeq
)

func (d DisorderMode) String() string {
	switch d {
	case DisorderNone:
		return "none"
	case DisorderTTLZero:
		return "ttl-zero"
	case DisorderOutOfBand:
		return "out-of-band"
	case DisorderBadSeq:
		return "bad-seq"
	default:
		return "unknown"
	}
}

// FakeMode определяет способ создания поддельных пакетов
type FakeMode int

const (
	FakeNone FakeMode = iota
	FakeMD5Sig
	FakeBadSeq
	FakeDataNoAck
	FakeWindowUpdate
)

func (f FakeMode) String() string {
	switch f {
	case FakeNone:
		return "none"
	case FakeMD5Sig:
		return "md5-sig"
	case FakeBadSeq:
		return "bad-seq"
	case FakeDataNoAck:
		return "data-noack"
	case FakeWindowUpdate:
		return "window-update"
	default:
		return "unknown"
	}
}

// HTTPModMode определяет модификации HTTP
type HTTPModMode int

const (
	HTTPModNone HTTPModMode = iota
	HTTPModHostCase
	HTTPModExtraSpace
	HTTPModDotAtEnd
	HTTPModAll
)

// Strategy представляет стратегию обхода DPI
type Strategy struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// Применять к каким протоколам
	ApplyToHTTP bool `json:"apply_to_http"`
	ApplyToTLS  bool `json:"apply_to_tls"`
	ApplyToQUIC bool `json:"apply_to_quic"`

	// Параметры разбиения
	SplitMode      SplitMode `json:"split_mode"`
	SplitPositions []int     `json:"split_positions"`  // позиции для разбиения
	SplitSNIOffset bool      `json:"split_sni_offset"` // смещение относительно SNI

	// Параметры нарушения порядка
	DisorderMode    DisorderMode `json:"disorder_mode"`
	DisorderPos     []int        `json:"disorder_pos"`     // позиции для disorder
	DisorderTTL     int          `json:"disorder_ttl"`     // TTL для disorder-пакетов
	DisorderRepeats int          `json:"disorder_repeats"` // количество повторений

	// Параметры поддельных пакетов
	FakeMode    FakeMode `json:"fake_mode"`
	FakePos     int      `json:"fake_pos"`     // позиция для fake
	FakeTTL     int      `json:"fake_ttl"`     // TTL для fake
	FakeRepeats int      `json:"fake_repeats"` // количество фейков

	// Модификация HTTP
	HTTPModMode HTTPModMode `json:"http_mod_mode"`
	HostCase    bool        `json:"host_case"`   // изменение регистра Host:
	ExtraSpace  bool        `json:"extra_space"` // добавление пробела после метода
	DotAtEnd    bool        `json:"dot_at_end"`  // точка в конце Host:

	// TLS-специфичные параметры
	TLSRecordSplit bool `json:"tls_record_split"` // разделение TLS-записей
	TLSRecordSize  int  `json:"tls_record_size"`  // размер TLS-записи

	// Прочее
	WindowSize int `json:"window_size"` // изменение TCP window size
	IPID       int `json:"ip_id"`       // изменение IP ID
	TTL        int `json:"ttl"`         // изменение TTL
	DupCount   int `json:"dup_count"`   // количество дубликатов
	DupTTL     int `json:"dup_ttl"`     // TTL для дубликатов

	// Метаданные
	Priority      int       `json:"priority"`      // приоритет (меньше = выше)
	SuccessCount  int       `json:"success_count"` // сколько раз успешно применилась
	FailCount     int       `json:"fail_count"`    // сколько раз провалилась
	LastUsed      time.Time `json:"last_used"`
	AvgResponseMs int64     `json:"avg_response_ms"` // среднее время ответа
}

// Clone создает копию стратегии
func (s *Strategy) Clone() *Strategy {
	clone := *s
	clone.SplitPositions = make([]int, len(s.SplitPositions))
	copy(clone.SplitPositions, s.SplitPositions)
	clone.DisorderPos = make([]int, len(s.DisorderPos))
	copy(clone.DisorderPos, s.DisorderPos)
	return &clone
}

// String возвращает строковое представление
func (s *Strategy) String() string {
	return fmt.Sprintf("%s(split=%v,disorder=%v,fake=%v)",
		s.Name, s.SplitMode, s.DisorderMode, s.FakeMode)
}

// StrategyFilter фильтр для выбора стратегий
type StrategyFilter struct {
	Protocol  string // "tcp", "udp", "all"
	Ports     []int
	Hostnames []string
	IPRanges  []string
	Country   string
	ASN       int
}

// StrategyResult результат применения стратегии
type StrategyResult struct {
	StrategyID   int
	Success      bool
	ResponseTime time.Duration
	BytesSent    int
	PacketsSent  int
	Error        string
	Timestamp    time.Time
}
