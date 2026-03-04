//go:build android || ios
// +build android ios

package core

import (
	"log"
	"sync"
	"time"

	"ByPass/pkg/api"
)

var (
	mobileCore   *MobileCore
	mobileCoreMu sync.Mutex
)

// MobileCore ядро для мобильных устройств
type MobileCore struct {
	config     *api.MobileConfig
	running    bool
	proxyPort  int
	bypassMu   sync.RWMutex
	bypassList map[string]bool
	stats      api.MobileStats
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
func StartMobile(config api.MobileConfig) error {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

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
func GetMobileStats() api.MobileStats {
	mobileCoreMu.Lock()
	defer mobileCoreMu.Unlock()

	if mobileCore == nil {
		return api.MobileStats{}
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
func (m *MobileCore) start(config api.MobileConfig) error {
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
func (m *MobileCore) getStats() api.MobileStats {
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

// shouldBypass проверяет, нужно ли обходить домен
func (m *MobileCore) shouldBypass(domain string) bool {
	m.bypassMu.RLock()
	defer m.bypassMu.RUnlock()
	return m.bypassList[domain]
}
