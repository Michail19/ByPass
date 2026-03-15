package config

import (
	"fmt"
	"net"
	"strings"
)

// Validate проверяет конфигурацию на корректность
func (c *Config) Validate() error {
	if err := c.Capture.Validate(); err != nil {
		return fmt.Errorf("capture: %v", err)
	}

	if err := c.Firewall.Validate(); err != nil {
		return fmt.Errorf("firewall: %v", err)
	}

	if err := c.Conntrack.Validate(); err != nil {
		return fmt.Errorf("conntrack: %v", err)
	}

	if err := c.Cache.Validate(); err != nil {
		return fmt.Errorf("cache: %v", err)
	}

	if err := c.Strategy.Validate(); err != nil {
		return fmt.Errorf("strategy: %v", err)
	}

	if err := c.Pipeline.Validate(); err != nil {
		return fmt.Errorf("pipeline: %v", err)
	}

	if err := c.Sender.Validate(); err != nil {
		return fmt.Errorf("sender: %v", err)
	}

	if err := c.Logging.Validate(); err != nil {
		return fmt.Errorf("logging: %v", err)
	}

	return nil
}

// Validate проверяет конфигурацию захвата
func (c *CaptureConfig) Validate() error {
	validTypes := map[string]bool{
		"nfqueue":   true,
		"windivert": true,
		"pcap":      true,
	}

	if !validTypes[c.Type] {
		return fmt.Errorf("invalid capture type: %s", c.Type)
	}

	if c.QueueNum < 0 || c.QueueNum > 65535 {
		return fmt.Errorf("queue_num must be between 0 and 65535")
	}

	if c.BufferSize < 1024 {
		return fmt.Errorf("buffer_size too small")
	}

	if c.MaxPacketLen < 64 {
		return fmt.Errorf("max_packet_len too small")
	}

	if c.Timeout < 0 {
		return fmt.Errorf("timeout must be non-negative")
	}

	return nil
}

// Validate проверяет конфигурацию файрвола
func (f *FirewallConfig) Validate() error {
	validBackends := map[string]bool{
		"iptables": true,
		"nftables": true,
		"windows":  true,
		"winfw":    true,
		"auto":     true,
	}

	if !validBackends[f.Backend] {
		return fmt.Errorf("invalid firewall backend: %s", f.Backend)
	}

	if len(f.Ports) == 0 {
		return fmt.Errorf("at least one port must be specified")
	}

	for _, port := range f.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %d", port)
		}
	}

	for _, port := range f.ExcludePorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid exclude port: %d", port)
		}
	}

	validDirections := map[string]bool{
		"outgoing": true,
		"incoming": true,
		"both":     true,
	}

	if !validDirections[f.Direction] {
		return fmt.Errorf("invalid direction: %s", f.Direction)
	}

	for _, ip := range f.ExcludeIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid exclude IP: %s", ip)
		}
	}

	return nil
}

// Validate проверяет конфигурацию conntrack
func (c *ConntrackConfig) Validate() error {
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if c.MaxFlows < 1 {
		return fmt.Errorf("max_flows must be at least 1")
	}
	if c.CleanupInterval <= 0 {
		return fmt.Errorf("cleanup_interval must be positive")
	}
	return nil
}

// Validate проверяет конфигурацию кэшей
func (c *CacheConfig) Validate() error {
	if c.IPCache.Enabled {
		if c.IPCache.TTL <= 0 {
			return fmt.Errorf("ip_cache.ttl must be positive when enabled")
		}
		if c.IPCache.MaxSize < 1 {
			return fmt.Errorf("ip_cache.max_size must be at least 1 when enabled")
		}
	}

	if c.DomainCache.Enabled {
		if c.DomainCache.TTL <= 0 {
			return fmt.Errorf("domain_cache.ttl must be positive when enabled")
		}
		if c.DomainCache.MaxSize < 1 {
			return fmt.Errorf("domain_cache.max_size must be at least 1 when enabled")
		}
		for _, host := range c.DomainCache.Preload {
			if strings.TrimSpace(host) == "" {
				return fmt.Errorf("domain_cache.preload contains empty hostname")
			}
		}
	}

	return nil
}

// Validate проверяет конфигурацию стратегий
func (s *StrategyConfig) Validate() error {
	for i, r := range s.HostnameRules {
		if strings.TrimSpace(r.Pattern) == "" {
			return fmt.Errorf("hostname_rules[%d]: pattern is required", i)
		}
		if strings.TrimSpace(r.Strategy) == "" && r.StrategyID <= 0 {
			return fmt.Errorf("hostname_rules[%d]: strategy or strategy_id is required", i)
		}
	}

	if s.AutoDiscovery.Enabled {
		if len(s.AutoDiscovery.TestDomains) == 0 {
			return fmt.Errorf("test_domains required for auto-discovery")
		}

		if len(s.AutoDiscovery.TestPorts) == 0 {
			return fmt.Errorf("test_ports required for auto-discovery")
		}

		for _, p := range s.AutoDiscovery.TestPorts {
			if p < 1 || p > 65535 {
				return fmt.Errorf("invalid auto_discovery test port: %d", p)
			}
		}

		if s.AutoDiscovery.TestInterval <= 0 {
			return fmt.Errorf("test_interval must be positive")
		}

		if s.AutoDiscovery.MinSuccessRate < 0 || s.AutoDiscovery.MinSuccessRate > 1 {
			return fmt.Errorf("min_success_rate must be between 0 and 1")
		}
	}

	return nil
}

// Validate проверяет конфигурацию конвейера
func (p *PipelineConfig) Validate() error {
	if p.Workers < 1 {
		return fmt.Errorf("workers must be at least 1")
	}

	if p.PacketQueueSize < 100 {
		return fmt.Errorf("packet_queue_size too small")
	}

	if p.ResultQueueSize < 1 {
		return fmt.Errorf("result_queue_size must be at least 1")
	}

	if p.ProcessTimeout < 0 {
		return fmt.Errorf("process_timeout must be non-negative")
	}

	return nil
}

// Validate проверяет конфигурацию отправителя
func (s *SenderConfig) Validate() error {
	if s.Type != "" && s.Type != "raw" {
		return fmt.Errorf("unsupported sender type: %s", s.Type)
	}
	if s.BufferSize < 1024 {
		return fmt.Errorf("buffer_size too small")
	}
	if s.SendTimeout < 0 {
		return fmt.Errorf("send_timeout must be non-negative")
	}
	if s.BatchSize < 1 {
		return fmt.Errorf("batch_size must be at least 1")
	}
	return nil
}

// Validate проверяет конфигурацию логирования
func (l *LoggingConfig) Validate() error {
	validOutputs := map[string]bool{
		"":       true,
		"stdout": true,
		"stderr": true,
		"file":   true,
	}

	if !validOutputs[l.Output] {
		return fmt.Errorf("invalid output: %s", l.Output)
	}

	if l.Output == "file" && strings.TrimSpace(l.FilePath) == "" {
		return fmt.Errorf("file_path is required when output=file")
	}

	if l.MaxSize < 0 {
		return fmt.Errorf("max_size must be non-negative")
	}
	if l.MaxBackups < 0 {
		return fmt.Errorf("max_backups must be non-negative")
	}

	return nil
}

// Merge объединяет две конфигурации (значения из other перезаписывают)
func (c *Config) Merge(other *Config) {
	// Здесь можно реализовать глубокое слияние конфигураций
	// Для простоты пока оставляем как есть
}
