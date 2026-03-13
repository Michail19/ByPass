package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// IPTablesManager управляет правилами iptables
type IPTablesManager struct {
	cfg Config
}

// NewIPTablesManager создает новый менеджер для iptables
func NewIPTablesManager(cfg Config) (*IPTablesManager, error) {
	// Проверяем наличие iptables
	if _, err := exec.LookPath("iptables"); err != nil {
		return nil, fmt.Errorf("iptables not found: %v", err)
	}

	return &IPTablesManager{cfg: cfg}, nil
}

func chainsForDirection(direction string) []string {
	switch direction {
	case DirectionIncoming:
		return []string{"INPUT"}
	case DirectionBoth:
		return []string{"OUTPUT", "INPUT"}
	default:
		return []string{"OUTPUT"}
	}
}

func hasPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

func (m *IPTablesManager) AddRule(queueNum int, ports []int, direction string) error {
	tcpPortStr := buildPortString(ports)
	if tcpPortStr == "" {
		return fmt.Errorf("no ports specified")
	}

	for _, chain := range chainsForDirection(direction) {
		if err := m.ensureNFQueueRule(queueNum, tcpPortStr, chain, "tcp"); err != nil {
			return err
		}
		if hasPort(ports, 443) {
			if err := m.ensureNFQueueRule(queueNum, "443", chain, "udp"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *IPTablesManager) RemoveRule(queueNum int, ports []int, direction string) error {
	tcpPortStr := buildPortString(ports)
	if tcpPortStr == "" {
		return nil
	}

	for _, chain := range chainsForDirection(direction) {
		if err := m.deleteNFQueueRule(queueNum, tcpPortStr, chain, "tcp"); err != nil {
			return err
		}
		if hasPort(ports, 443) {
			if err := m.deleteNFQueueRule(queueNum, "443", chain, "udp"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *IPTablesManager) ensureNFQueueRule(queueNum int, portStr, chain, proto string) error {
	checkArgs := []string{
		"-t", "mangle",
		"-C", chain,
		"-p", proto,
		"-m", "multiport",
		"--dports", portStr,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
	}
	if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
		return nil
	}

	args := []string{
		"-t", "mangle",
		"-I", chain,
		"-p", proto,
		"-m", "multiport",
		"--dports", portStr,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
	}
	for _, ip := range m.cfg.ExcludeIPs {
		args = append([]string{"!", "-d", ip}, args...)
	}

	return runCommand("iptables", args...)
}

func (m *IPTablesManager) deleteNFQueueRule(queueNum int, portStr, chain, proto string) error {
	checkArgs := []string{
		"-t", "mangle",
		"-C", chain,
		"-p", proto,
		"-m", "multiport",
		"--dports", portStr,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
	}
	if err := exec.Command("iptables", checkArgs...).Run(); err != nil {
		return nil // правила уже нет
	}

	args := []string{
		"-t", "mangle",
		"-D", chain,
		"-p", proto,
		"-m", "multiport",
		"--dports", portStr,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
	}
	for _, ip := range m.cfg.ExcludeIPs {
		args = append([]string{"!", "-d", ip}, args...)
	}

	return runCommand("iptables", args...)
}

// ClearRules очищает все правила
func (m *IPTablesManager) ClearRules() error {
	// Получаем список правил
	rules, err := m.ListRules()
	if err != nil {
		return err
	}

	// Удаляем каждое правило
	for _, rule := range rules {
		args := strings.Fields(rule)
		if len(args) > 0 {
			runCommand("iptables", args...)
		}
	}

	return nil
}

// ListRules возвращает список правил
func (m *IPTablesManager) ListRules() ([]string, error) {
	cmd := exec.Command("iptables", "-t", "mangle", "-L", "OUTPUT", "-n", "-v")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var rules []string

	for _, line := range lines {
		if strings.Contains(line, "NFQUEUE") {
			rules = append(rules, line)
		}
	}

	return rules, nil
}

// IsSupported проверяет поддержку
func (m *IPTablesManager) IsSupported() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}
