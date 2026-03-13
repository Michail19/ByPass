package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// NFTablesManager управляет правилами nftables
type NFTablesManager struct {
	cfg     Config
	table   string
	chain   string
	setName string
}

// NewNFTablesManager создает новый менеджер для nftables
func NewNFTablesManager(cfg Config) (*NFTablesManager, error) {
	// Проверяем наличие nft
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("nft not found: %v", err)
	}

	return &NFTablesManager{
		cfg:     cfg,
		table:   "mydpi",
		chain:   "mydpi_output",
		setName: "mydpi_ports",
	}, nil
}

// AddRule добавляет правило nftables
func (m *NFTablesManager) AddRule(queueNum int, ports []int, direction string) error {
	// Создаем таблицу и цепочку если не существуют
	if err := m.ensureTable(); err != nil {
		return err
	}

	// Создаем набор портов
	if err := m.createPortSet(ports); err != nil {
		return err
	}

	// Добавляем правило
	return m.addQueueRule(queueNum, direction)
}

// ensureTable создает таблицу и цепочку если их нет
func (m *NFTablesManager) ensureTable() error {
	checkTable := exec.Command("nft", "list", "table", "inet", m.table)
	if err := checkTable.Run(); err != nil {
		createTable := fmt.Sprintf("nft add table inet %s", m.table)
		if err := runCommand("bash", "-c", createTable); err != nil {
			return err
		}
	}

	checkChain := exec.Command("nft", "list", "chain", "inet", m.table, m.chain)
	if err := checkChain.Run(); err != nil {
		createChain := fmt.Sprintf(
			"nft add chain inet %s %s { type filter hook output priority 0\\; }",
			m.table, m.chain,
		)
		if err := runCommand("bash", "-c", createChain); err != nil {
			return err
		}
	}

	return nil
}

// createPortSet создает набор портов
func (m *NFTablesManager) createPortSet(ports []int) error {
	// Удаляем старый набор если есть
	delCmd := fmt.Sprintf("nft delete set inet %s %s 2>/dev/null || true", m.table, m.setName)
	runCommand("bash", "-c", delCmd)

	// Создаем новый набор
	var elements []string
	for _, p := range ports {
		elements = append(elements, fmt.Sprintf("%d", p))
	}

	createSet := fmt.Sprintf(
		"nft add set inet %s %s { type inet_service\\; elements = { %s }\\; }",
		m.table, m.setName, strings.Join(elements, ", "))

	return runCommand("bash", "-c", createSet)
}

// addQueueRule добавляет правило для NFQUEUE
func (m *NFTablesManager) addQueueRule(queueNum int, direction string) error {
	tcpCmd := fmt.Sprintf(
		"nft add rule inet %s %s tcp dport @%s counter queue num %d bypass",
		m.table, m.chain, m.setName, queueNum,
	)
	if err := runCommand("bash", "-c", tcpCmd); err != nil {
		return err
	}

	udpCmd := fmt.Sprintf(
		"nft add rule inet %s %s udp dport 443 counter queue num %d bypass",
		m.table, m.chain, queueNum,
	)
	return runCommand("bash", "-c", udpCmd)
}

// RemoveRule удаляет правило nftables
func (m *NFTablesManager) RemoveRule(queueNum int, ports []int, direction string) error {
	cmd := fmt.Sprintf(
		`for h in $(nft -a list chain inet %s %s | awk '/queue num %d/ {print $NF}'); do nft delete rule inet %s %s handle $h; done`,
		m.table, m.chain, queueNum, m.table, m.chain,
	)
	return runCommand("bash", "-c", cmd)
}

// ClearRules очищает все правила
func (m *NFTablesManager) ClearRules() error {
	// Удаляем таблицу полностью
	cmd := fmt.Sprintf("nft delete table inet %s 2>/dev/null || true", m.table)
	return runCommand("bash", "-c", cmd)
}

// ListRules возвращает список правил
func (m *NFTablesManager) ListRules() ([]string, error) {
	cmd := exec.Command("nft", "list", "chain", "inet", m.table, m.chain)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var rules []string

	for _, line := range lines {
		if strings.Contains(line, "queue") {
			rules = append(rules, line)
		}
	}

	return rules, nil
}

// IsSupported проверяет поддержку
func (m *NFTablesManager) IsSupported() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}
