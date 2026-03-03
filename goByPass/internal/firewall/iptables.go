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

// AddRule добавляет правило iptables
func (m *IPTablesManager) AddRule(queueNum int, ports []int, direction string) error {
	portStr := buildPortString(ports)
	if portStr == "" {
		return fmt.Errorf("no ports specified")
	}

	// Определяем цепочку в зависимости от направления
	chain := "OUTPUT"
	if direction == DirectionIncoming {
		chain = "INPUT"
	} else if direction == DirectionBoth {
		// Добавляем правила для обеих цепочек
		if err := m.addRuleToChain(queueNum, portStr, "OUTPUT"); err != nil {
			return err
		}
		return m.addRuleToChain(queueNum, portStr, "INPUT")
	}

	return m.addRuleToChain(queueNum, portStr, chain)
}

// addRuleToChain добавляет правило в конкретную цепочку
func (m *IPTablesManager) addRuleToChain(queueNum int, portStr, chain string) error {
	// Проверяем, существует ли уже правило
	checkCmd := exec.Command("iptables", "-t", "mangle", "-C", chain,
		"-p", "tcp", "-m", "multiport", "--dports", portStr,
		"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", queueNum), "--queue-bypass")

	if err := checkCmd.Run(); err == nil {
		return nil // правило уже существует
	}

	// Добавляем правило
	args := []string{
		"-t", "mangle",
		"-I", chain,
		"-p", "tcp",
		"-m", "multiport",
		"--dports", portStr,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
	}

	// Добавляем исключения
	for _, ip := range m.cfg.ExcludeIPs {
		args = append([]string{"!", "-d", ip}, args...)
	}

	return runCommand("iptables", args...)
}

// RemoveRule удаляет правило iptables
func (m *IPTablesManager) RemoveRule(queueNum int, ports []int, direction string) error {
	portStr := buildPortString(ports)
	if portStr == "" {
		return nil
	}

	if direction == DirectionBoth {
		if err := m.removeRuleFromChain(queueNum, portStr, "OUTPUT"); err != nil {
			return err
		}
		return m.removeRuleFromChain(queueNum, portStr, "INPUT")
	}

	chain := "OUTPUT"
	if direction == DirectionIncoming {
		chain = "INPUT"
	}

	return m.removeRuleFromChain(queueNum, portStr, chain)
}

// removeRuleFromChain удаляет правило из цепочки
func (m *IPTablesManager) removeRuleFromChain(queueNum int, portStr, chain string) error {
	args := []string{
		"-t", "mangle",
		"-D", chain,
		"-p", "tcp",
		"-m", "multiport",
		"--dports", portStr,
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
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
