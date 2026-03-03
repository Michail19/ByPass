package config

import (
	"fmt"
	"net"
)

// Validate проверяет конфигурацию на корректность
func (c *Config) Validate() error {
	// Проверяем захват
	if err := c.Capture.Validate(); err != nil {
		return fmt.Errorf("capture: %v", err)
	}

	// Проверяем файрвол
	if err := c.Firewall.Validate(); err != nil {
		return fmt.Errorf("firewall: %v", err)
	}

	// Проверяем конвейер
	if err := c.Pipeline.Validate(); err != nil {
		return fmt.Errorf("pipeline: %v", err)
	}

	// Проверяем конфигурацию стратегий
	if err := c.Strategy.Validate(); err != nil {
		return fmt.Errorf("strategy: %v", err)
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

	return nil
}

// Validate проверяет конфигурацию файрвола
func (f *FirewallConfig) Validate() error {
	validBackends := map[string]bool{
		"iptables": true,
		"nftables": true,
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

	validDirections := map[string]bool{
		"outgoing": true,
		"incoming": true,
		"both":     true,
	}

	if !validDirections[f.Direction] {
		return fmt.Errorf("invalid direction: %s", f.Direction)
	}

	// Проверяем исключенные IP
	for _, ip := range f.ExcludeIPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid exclude IP: %s", ip)
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

	if p.ProcessTimeout < 0 {
		return fmt.Errorf("process_timeout must be positive")
	}

	return nil
}

// Validate проверяет конфигурацию стратегий
func (s *StrategyConfig) Validate() error {
	if s.AutoDiscovery.Enabled {
		if len(s.AutoDiscovery.TestDomains) == 0 {
			return fmt.Errorf("test_domains required for auto-discovery")
		}

		if s.AutoDiscovery.MinSuccessRate < 0 || s.AutoDiscovery.MinSuccessRate > 1 {
			return fmt.Errorf("min_success_rate must be between 0 and 1")
		}
	}

	return nil
}

// Merge объединяет две конфигурации (значения из other перезаписывают)
func (c *Config) Merge(other *Config) {
	// Здесь можно реализовать глубокое слияние конфигураций
	// Для простоты пока оставляем как есть
}
