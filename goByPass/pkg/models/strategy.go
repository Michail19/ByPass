package models

import "time"

// StrategyMode режим стратегии
type StrategyMode string

const (
	StrategyModeSplit    StrategyMode = "split"
	StrategyModeDisorder StrategyMode = "disorder"
	StrategyModeFake     StrategyMode = "fake"
	StrategyModeHTTP     StrategyMode = "http"
	StrategyModeTLS      StrategyMode = "tls"
)

// Strategy представляет стратегию обхода
type Strategy struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// Применение
	ApplyToHTTP bool `json:"apply_to_http"`
	ApplyToTLS  bool `json:"apply_to_tls"`
	ApplyToQUIC bool `json:"apply_to_quic"`

	// Параметры
	SplitMode      string `json:"split_mode"`
	SplitPositions []int  `json:"split_positions"`

	DisorderMode string `json:"disorder_mode"`
	DisorderTTL  int    `json:"disorder_ttl"`

	FakeMode string `json:"fake_mode"`
	FakeTTL  int    `json:"fake_ttl"`

	HTTPModMode    string `json:"http_mod_mode"`
	TLSRecordSplit bool   `json:"tls_record_split"`

	// Статистика
	SuccessCount int       `json:"success_count"`
	FailCount    int       `json:"fail_count"`
	LastUsed     time.Time `json:"last_used"`
	Priority     int       `json:"priority"`
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
