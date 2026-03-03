package config

import (
	_ "encoding/json"
	_ "fmt"
	_ "os"
	"time"

	_ "gopkg.in/yaml.v3"
)

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
	Type         string        `yaml:"type" json:"type"`               // "nfqueue", "windivert", "pcap"
	QueueNum     int           `yaml:"queue_num" json:"queue_num"`     // номер очереди NFQUEUE
	BufferSize   int           `yaml:"buffer_size" json:"buffer_size"` // размер буфера
	Interface    string        `yaml:"interface" json:"interface"`     // интерфейс (пустая строка = все)
	MaxPacketLen int           `yaml:"max_packet_len" json:"max_packet_len"`
	Promiscuous  bool          `yaml:"promiscuous" json:"promiscuous"`
	Timeout      time.Duration `yaml:"timeout" json:"timeout"`
}

// FirewallConfig конфигурация файрвола
type FirewallConfig struct {
	Backend       string   `yaml:"backend" json:"backend"`             // "iptables", "nftables", "auto"
	Ports         []int    `yaml:"ports" json:"ports"`                 // порты для обработки (80,443)
	Direction     string   `yaml:"direction" json:"direction"`         // "outgoing", "incoming", "both"
	ExcludeIPs    []string `yaml:"exclude_ips" json:"exclude_ips"`     // исключить IP
	ExcludePorts  []int    `yaml:"exclude_ports" json:"exclude_ports"` // исключить порты
	CleanupOnExit bool     `yaml:"cleanup_on_exit" json:"cleanup_on_exit"`
}

// ConntrackConfig конфигурация отслеживания потоков
type ConntrackConfig struct {
	Timeout         time.Duration `yaml:"timeout" json:"timeout"`     // таймаут потока
	MaxFlows        int           `yaml:"max_flows" json:"max_flows"` // максимум потоков
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
		Preload []string      `yaml:"preload" json:"preload"` // домены для предзагрузки
	} `yaml:"domain_cache" json:"domain_cache"`
}

// StrategyConfig конфигурация стратегий
type StrategyConfig struct {
	DefaultStrategy string `yaml:"default_strategy" json:"default_strategy"` // имя стратегии по умолчанию
	StrategyFile    string `yaml:"strategy_file" json:"strategy_file"`       // файл с кастомными стратегиями
	AutoDiscovery   struct {
		Enabled        bool     `yaml:"enabled" json:"enabled"`
		TestDomains    []string `yaml:"test_domains" json:"test_domains"`
		TestPorts      []int    `yaml:"test_ports" json:"test_ports"`
		TestInterval   int      `yaml:"test_interval" json:"test_interval"` // секунды
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
	Type        string        `yaml:"type" json:"type"`               // "raw", "pcap", "tun"
	Interface   string        `yaml:"interface" json:"interface"`     // интерфейс отправки
	BufferSize  int           `yaml:"buffer_size" json:"buffer_size"` // размер буфера
	SendTimeout time.Duration `yaml:"send_timeout" json:"send_timeout"`
	BatchSize   int           `yaml:"batch_size" json:"batch_size"` // пакетов в батче
}

// LoggingConfig конфигурация логирования
type LoggingConfig struct {
	Level      string `yaml:"level" json:"level"`             // debug, info, warn, error
	Output     string `yaml:"output" json:"output"`           // stdout, stderr, file
	FilePath   string `yaml:"file_path" json:"file_path"`     // путь к файлу лога
	MaxSize    int    `yaml:"max_size" json:"max_size"`       // максимальный размер файла (MB)
	MaxBackups int    `yaml:"max_backups" json:"max_backups"` // количество бэкапов
	Compress   bool   `yaml:"compress" json:"compress"`       // сжимать ли бэкапы
}
