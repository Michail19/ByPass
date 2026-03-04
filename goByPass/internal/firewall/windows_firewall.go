//go:build windows
// +build windows

package firewall

import (
	"os/exec"
	"strings"
)

// WindowsFirewallManager управляет правилами Windows Firewall
type WindowsFirewallManager struct {
	cfg Config
}

// NewWindowsFirewallManager создает новый менеджер для Windows Firewall
func NewWindowsFirewallManager(cfg Config) (*WindowsFirewallManager, error) {
	return &WindowsFirewallManager{cfg: cfg}, nil
}

// AddRule добавляет правило в Windows Firewall
func (m *WindowsFirewallManager) AddRule(queueNum int, ports []int, direction string) error {
	// Для Windows мы не можем использовать NFQUEUE, поэтому
	// просто проверяем, что приложение имеет права
	return m.checkAdminRights()
}

// RemoveRule удаляет правило
func (m *WindowsFirewallManager) RemoveRule(queueNum int, ports []int, direction string) error {
	return nil
}

// ClearRules очищает все правила
func (m *WindowsFirewallManager) ClearRules() error {
	return nil
}

// ListRules возвращает список правил
func (m *WindowsFirewallManager) ListRules() ([]string, error) {
	// Выполняем netsh advfirewall для получения правил
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	return lines, nil
}

// IsSupported проверяет поддержку
func (m *WindowsFirewallManager) IsSupported() bool {
	// Проверяем, запущены ли мы с правами администратора
	return isAdmin()
}

// checkAdminRights проверяет права администратора
func (m *WindowsFirewallManager) checkAdminRights() error {
	if !isAdmin() {
		return ErrPermissionDenied
	}
	return nil
}

// isAdmin проверяет, запущен ли процесс с правами администратора
func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}
