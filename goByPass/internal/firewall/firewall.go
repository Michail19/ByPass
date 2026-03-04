package firewall

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Manager определяет интерфейс для управления файрволом
type Manager interface {
	// AddRule добавляет правило для перенаправления трафика в NFQUEUE
	AddRule(queueNum int, ports []int, direction string) error

	// RemoveRule удаляет правило
	RemoveRule(queueNum int, ports []int, direction string) error

	// ClearRules очищает все правила
	ClearRules() error

	// ListRules возвращает список активных правил
	ListRules() ([]string, error)

	// IsSupported проверяет, поддерживается ли бэкенд
	IsSupported() bool
}

// Config конфигурация файрвола
type Config struct {
	Backend       string   // "iptables", "nftables", "auto"
	QueueNum      int      // номер очереди NFQUEUE
	Ports         []int    // порты для обработки
	Direction     string   // "outgoing", "incoming", "both"
	ExcludeIPs    []string // исключить IP-адреса
	ExcludePorts  []int    // исключить порты
	CleanupOnExit bool     // очищать правила при выходе
}

// Direction константы для направления трафика
const (
	DirectionOutgoing = "outgoing"
	DirectionIncoming = "incoming"
	DirectionBoth     = "both"
)

// Общие ошибки
var (
	ErrNotSupported     = errors.New("firewall backend not supported")
	ErrPermissionDenied = errors.New("permission denied (need root)")
	ErrRuleExists       = errors.New("rule already exists")
	ErrRuleNotFound     = errors.New("rule not found")
)

// NewManager создает менеджер файрвола в зависимости от бэкенда и платформы
func NewManager(cfg Config) (Manager, error) {
	// Проверяем права администратора на Windows
	if runtime.GOOS == "windows" && !isAdmin() {
		return nil, ErrPermissionDenied
	}

	backend := cfg.Backend
	if backend == "auto" {
		backend = detectBackend()
	}

	switch backend {
	case "iptables":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("%w: iptables is Linux-only", ErrNotSupported)
		}
		return NewIPTablesManager(cfg)
	case "nftables":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("%w: nftables is Linux-only", ErrNotSupported)
		}
		return NewNFTablesManager(cfg)
	case "windows", "winfw":
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("%w: Windows Firewall is Windows-only", ErrNotSupported)
		}
		return NewWindowsFirewallManager(cfg)
	default:
		// Для Windows по умолчанию используем свой менеджер
		if runtime.GOOS == "windows" {
			return NewWindowsFirewallManager(cfg)
		}
		return nil, fmt.Errorf("%w: %s", ErrNotSupported, backend)
	}
}

// detectBackend определяет доступный бэкенд
func detectBackend() string {
	// Проверяем nftables
	if _, err := exec.LookPath("nft"); err == nil {
		// Проверяем, что nftables действительно работает
		cmd := exec.Command("nft", "list", "tables")
		if err := cmd.Run(); err == nil {
			return "nftables"
		}
	}

	// Проверяем iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		return "iptables"
	}

	return "none"
}

// isRoot проверяет, запущен ли процесс от root
func isRoot() bool {
	return runtime.GOOS != "windows" // упрощенно
}

// buildPortString создает строку с портами для правил
func buildPortString(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	strPorts := make([]string, len(ports))
	for i, p := range ports {
		strPorts[i] = fmt.Sprintf("%d", p)
	}

	if len(ports) == 1 {
		return strPorts[0]
	}

	return strings.Join(strPorts, ",")
}

// runCommand выполняет команду и возвращает ошибку
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("command failed: %s %v: %s - %v", name, args, string(output), err)
	}
	return nil
}
