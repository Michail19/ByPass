package config

import "time"

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		App: AppConfig{
			Name:       "ByPass",
			Version:    "1.0.0",
			PidFile:    "/var/run/mydpi.pid",
			WorkingDir: "/etc/mydpi",
			Daemonize:  false,
		},

		Capture: CaptureConfig{
			Type:         "nfqueue",
			QueueNum:     0,
			BufferSize:   65535,
			Interface:    "any",
			MaxPacketLen: 65535,
			Promiscuous:  false,
			Timeout:      100 * time.Millisecond,
		},

		Firewall: FirewallConfig{
			Backend:       "auto",
			Ports:         []int{80, 443},
			Direction:     "outgoing",
			ExcludeIPs:    []string{},
			ExcludePorts:  []int{},
			CleanupOnExit: true,
		},

		Conntrack: ConntrackConfig{
			Timeout:         5 * time.Minute,
			MaxFlows:        100000,
			CleanupInterval: 30 * time.Second,
		},

		Cache: CacheConfig{
			IPCache: struct {
				Enabled bool          `yaml:"enabled" json:"enabled"`
				TTL     time.Duration `yaml:"ttl" json:"ttl"`
				MaxSize int           `yaml:"max_size" json:"max_size"`
			}{
				Enabled: true,
				TTL:     1 * time.Hour,
				MaxSize: 10000,
			},
			DomainCache: struct {
				Enabled bool          `yaml:"enabled" json:"enabled"`
				TTL     time.Duration `yaml:"ttl" json:"ttl"`
				MaxSize int           `yaml:"max_size" json:"max_size"`
				Preload []string      `yaml:"preload" json:"preload"`
			}{
				Enabled: true,
				TTL:     1 * time.Hour,
				MaxSize: 5000,
				Preload: []string{
					"google.com",
					"youtube.com",
					"discord.com",
					"telegram.org",
				},
			},
		},

		Strategy: StrategyConfig{
			DefaultStrategy: "moderate",
			StrategyFile:    "/etc/mydpi/strategies.json",
			AutoDiscovery: struct {
				Enabled        bool     `yaml:"enabled" json:"enabled"`
				TestDomains    []string `yaml:"test_domains" json:"test_domains"`
				TestPorts      []int    `yaml:"test_ports" json:"test_ports"`
				TestInterval   int      `yaml:"test_interval" json:"test_interval"`
				MinSuccessRate float64  `yaml:"min_success_rate" json:"min_success_rate"`
			}{
				Enabled: false,
				TestDomains: []string{
					"google.com",
					"youtube.com",
					"discord.com",
				},
				TestPorts:      []int{443},
				TestInterval:   3600,
				MinSuccessRate: 0.7,
			},
		},

		Pipeline: PipelineConfig{
			Workers:         4,
			PacketQueueSize: 10000,
			ResultQueueSize: 1000,
			ProcessTimeout:  100 * time.Millisecond,
		},

		Sender: SenderConfig{
			Type:        "raw",
			Interface:   "",
			BufferSize:  65535,
			SendTimeout: 1 * time.Second,
			BatchSize:   10,
		},

		Logging: LoggingConfig{
			Level:      "info",
			Output:     "stdout",
			FilePath:   "/var/log/mydpi.log",
			MaxSize:    10,
			MaxBackups: 3,
			Compress:   true,
		},
	}
}
