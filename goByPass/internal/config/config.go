package config

import (
	"time"
)

// HostnameRuleConfig правило маршрутизации hostname→стратегия в конфиге.
//
// Определено в пакете config (а не strategy) чтобы избежать циклического импорта.
// В main.go конвертируется в []strategy.HostnameRule перед передачей в Manager.
//
// Пример YAML:
//
//	hostname_rules:
//	  - pattern: "*.youtube.com"
//	    strategy: "yt-discord-2026-zapret"
//	    comment: "YouTube основной"
//	  - pattern: "*.discord.com"
//	    strategy: "discord-2026"
type HostnameRuleConfig struct {
	// Pattern — SNI/Host паттерн.
	// "*.youtube.com" → wildcard (любой субдомен + bare domain)
	// "youtube.com"   → точное совпадение
	Pattern string `yaml:"pattern" json:"pattern"`

	// Strategy — подстрока имени стратегии из strategies.json.
	// Приоритет над StrategyID.
	Strategy string `yaml:"strategy" json:"strategy"`

	// StrategyID — числовой ID стратегии.
	// Используется если Strategy не задан или не найден.
	StrategyID int `yaml:"strategy_id,omitempty" json:"strategy_id,omitempty"`

	// Comment — произвольный комментарий, выводится в лог при старте.
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Config основная конфигурация приложения
type Config struct {
	App       AppConfig       `yaml:"app" json:"app"`
	Capture   CaptureConfig   `yaml:"capture" json:"capture"`
	Firewall  FirewallConfig  `yaml:"firewall" json:"firewall"`
	Conntrack ConntrackConfig `yaml:"conntrack" json:"conntrack"`
	Cache     CacheConfig     `yaml:"cache" json:"cache"`
	Strategy  StrategyConfig  `yaml:"strategy" json:"strategy"`
	Pipeline  PipelineConfig  `yaml:"pipeline" json:"pipeline"`
	Sender    SenderConfig    `yaml:"sender" json:"sender"`
	Logging   LoggingConfig   `yaml:"logging" json:"logging"`
}

// AppConfig конфигурация приложения
type AppConfig struct {
	Name       string `yaml:"name" json:"name"`
	Version    string `yaml:"version" json:"version"`
	PidFile    string `yaml:"pid_file" json:"pid_file"`
	WorkingDir string `yaml:"working_dir" json:"working_dir"`
	Daemonize  bool   `yaml:"daemonize" json:"daemonize"`
}

// CaptureConfig конфигурация захвата
type CaptureConfig struct {
	Type         string        `yaml:"type" json:"type"`
	QueueNum     int           `yaml:"queue_num" json:"queue_num"`
	BufferSize   int           `yaml:"buffer_size" json:"buffer_size"`
	Interface    string        `yaml:"interface" json:"interface"`
	MaxPacketLen int           `yaml:"max_packet_len" json:"max_packet_len"`
	Promiscuous  bool          `yaml:"promiscuous" json:"promiscuous"`
	Timeout      time.Duration `yaml:"timeout" json:"timeout"`
}

// FirewallConfig конфигурация файрвола
type FirewallConfig struct {
	Backend       string   `yaml:"backend" json:"backend"`
	Ports         []int    `yaml:"ports" json:"ports"`
	Direction     string   `yaml:"direction" json:"direction"`
	ExcludeIPs    []string `yaml:"exclude_ips" json:"exclude_ips"`
	ExcludePorts  []int    `yaml:"exclude_ports" json:"exclude_ports"`
	CleanupOnExit bool     `yaml:"cleanup_on_exit" json:"cleanup_on_exit"`
}

// ConntrackConfig конфигурация отслеживания потоков
type ConntrackConfig struct {
	Timeout         time.Duration `yaml:"timeout" json:"timeout"`
	MaxFlows        int           `yaml:"max_flows" json:"max_flows"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
}

// CacheConfig конфигурация кэширования
type CacheConfig struct {
	IPCache struct {
		Enabled bool          `yaml:"enabled" json:"enabled"`
		TTL     time.Duration `yaml:"ttl" json:"ttl"`
		MaxSize int           `yaml:"max_size" json:"max_size"`
	} `yaml:"ip_cache" json:"ip_cache"`

	DomainCache struct {
		Enabled bool          `yaml:"enabled" json:"enabled"`
		TTL     time.Duration `yaml:"ttl" json:"ttl"`
		MaxSize int           `yaml:"max_size" json:"max_size"`
		Preload []string      `yaml:"preload" json:"preload"`
	} `yaml:"domain_cache" json:"domain_cache"`
}

// StrategyConfig конфигурация стратегий
type StrategyConfig struct {
	DefaultStrategy    string `yaml:"default_strategy" json:"default_strategy"`
	StrategyFile       string `yaml:"strategy_file" json:"strategy_file"`
	AppendDefaultRules bool   `yaml:"append_default_rules" json:"append_default_rules"`

	HostnameRules []HostnameRuleConfig `yaml:"hostname_rules" json:"hostname_rules"`

	AutoDiscovery struct {
		Enabled        bool     `yaml:"enabled" json:"enabled"`
		TestDomains    []string `yaml:"test_domains" json:"test_domains"`
		TestPorts      []int    `yaml:"test_ports" json:"test_ports"`
		TestInterval   int      `yaml:"test_interval" json:"test_interval"`
		MinSuccessRate float64  `yaml:"min_success_rate" json:"min_success_rate"`
	} `yaml:"auto_discovery" json:"auto_discovery"`
}

// PipelineConfig конфигурация конвейера
type PipelineConfig struct {
	Workers         int           `yaml:"workers" json:"workers"`
	PacketQueueSize int           `yaml:"packet_queue_size" json:"packet_queue_size"`
	ResultQueueSize int           `yaml:"result_queue_size" json:"result_queue_size"`
	ProcessTimeout  time.Duration `yaml:"process_timeout" json:"process_timeout"`
}

// SenderConfig конфигурация отправителя
type SenderConfig struct {
	Type        string        `yaml:"type" json:"type"`
	Interface   string        `yaml:"interface" json:"interface"`
	BufferSize  int           `yaml:"buffer_size" json:"buffer_size"`
	SendTimeout time.Duration `yaml:"send_timeout" json:"send_timeout"`
	BatchSize   int           `yaml:"batch_size" json:"batch_size"`
}

// LoggingConfig конфигурация логирования
type LoggingConfig struct {
	Level      string `yaml:"level" json:"level"`
	Output     string `yaml:"output" json:"output"`
	FilePath   string `yaml:"file_path" json:"file_path"`
	MaxSize    int    `yaml:"max_size" json:"max_size"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	Compress   bool   `yaml:"compress" json:"compress"`
}
