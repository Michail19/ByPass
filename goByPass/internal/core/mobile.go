//go:build android || ios
// +build android ios

package core

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// MobileConfig конфигурация для мобильных устройств (дублируем структуру)
type MobileConfig struct {
	ServerAddr    string   `json:"server_addr"`
	ServerPort    int      `json:"server_port"`
	Password      string   `json:"password"`
	Protocol      string   `json:"protocol"` // "trojan", "v2ray", "shadowsocks"
	EnableVPN     bool     `json:"enable_vpn"`
	BypassDomains []string `json:"bypass_domains"`
	ProxyPort     int      `json:"proxy_port"`
}

// MobileStats статистика для мобильных устройств (дублируем структуру)
type MobileStats struct {
	BytesReceived   int64 `json:"bytes_received"`
	BytesSent       int64 `json:"bytes_sent"`
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent     int64 `json:"packets_sent"`
	ActiveFlows     int   `json:"active_flows"`
	UptimeSeconds   int64 `json:"uptime_seconds"`
}

var (
	mobileCore   *MobileCore
	mobileCoreMu sync.Mutex
)

// MobileCore ядро для мобильных устройств
type MobileCore struct {
	config     *MobileConfig
	running    bool
	proxyPort  int
	bypassMu   sync.RWMutex
	bypassList map[string]bool
	stats      MobileStats
	startTime  time.Time
}

// NewMobileCore создает новое мобильное ядро
func NewMobileCore() *MobileCore {
	return &MobileCore{
		bypassList: make(map[string]bool),
		startTime:  time.Now(),
	}
}

// StartMobile запускает мобильное ядро
func StartMobile(configJSON interface{}) error {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

	// Конвертируем interface{} в MobileConfig
	var config MobileConfig
	jsonData, err := json.Marshal(configJSON)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return err
	}

	if mobileCore == nil {
		mobileCore = NewMobileCore()
	}

	return mobileCore.start(config)
}

// StopMobile останавливает мобильное ядро
func StopMobile() {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

	if mobileCore != nil {
		mobileCore.stop()
		mobileCore = nil
	}
}

// GetMobileStats возвращает статистику
func GetMobileStats() MobileStats {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

	if mobileCore == nil {
		return MobileStats{}
	}
	return mobileCore.getStats()
}

// SetProxyPort устанавливает порт прокси
func SetProxyPort(port int) {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

	if mobileCore != nil {
		mobileCore.proxyPort = port
	}
}

// AddBypassDomain добавляет домен для обхода
func AddBypassDomain(domain string) {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

	if mobileCore != nil {
		mobileCore.addBypassDomain(domain)
	}
}

// RemoveBypassDomain удаляет домен из списка обхода
func RemoveBypassDomain(domain string) {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

	if mobileCore != nil {
		mobileCore.removeBypassDomain(domain)
	}
}

// start запускает мобильное ядро
func (m *MobileCore) start(config MobileConfig) error {
	m.config = &config
	m.running = true
	m.startTime = time.Now()

	log.Printf("Mobile core started with config: %+v", config)

	// Здесь будет реальная логика для мобильных устройств
	// - Настройка VPNService
	// - Запуск прокси
	// - Подключение к серверу

	return nil
}

// stop останавливает мобильное ядро
func (m *MobileCore) stop() {
	m.running = false
	log.Println("Mobile core stopped")
}

// getStats возвращает статистику
func (m *MobileCore) getStats() MobileStats {
	m.bypassMu.RLock()
	defer m.bypassMu.RUnlock()

	m.stats.UptimeSeconds = int64(time.Since(m.startTime).Seconds())
	return m.stats
}

// addBypassDomain добавляет домен в список обхода
func (m *MobileCore) addBypassDomain(domain string) {
	m.bypassMu.Lock()
	defer m.bypassMu.Unlock()
	m.bypassList[domain] = true
	log.Printf("Added bypass domain: %s", domain)
}

// removeBypassDomain удаляет домен из списка обхода
func (m *MobileCore) removeBypassDomain(domain string) {
	m.bypassMu.Lock()
	defer m.bypassMu.Unlock()
	delete(m.bypassList, domain)
	log.Printf("Removed bypass domain: %s", domain)
}
