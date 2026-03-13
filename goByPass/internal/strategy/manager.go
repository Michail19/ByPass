package strategy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type ipRange struct {
	Prefix string `json:"ipv4Prefix"`
}

type googleIPList struct {
	SyncToken    string    `json:"syncToken"`
	CreationTime time.Time `json:"creationTime"`
	Prefixes     []ipRange `json:"prefixes"`
}

// strategyRuntimeStats хранит изменяемую статистику стратегии отдельно от
// конфига (Strategy). Strategy-указатель, возвращаемый SelectStrategy, становится
// иммутабельным после AddStrategy — вызывающий код может читать поля без блокировки.
// SuccessCount/FailCount/AvgResponseMs/LastUsed изменяются только через UpdateStrategy
// под statsMap[id].mu, а не через поля самой Strategy.
type strategyRuntimeStats struct {
	mu            sync.Mutex
	successCount  int
	failCount     int
	avgResponseMs int64
	lastUsed      time.Time
}

// Manager управляет стратегиями
type Manager struct {
	strategies     map[int]*Strategy
	defaultID      int
	activeID       int
	filters        map[string]*StrategyFilter
	stats          ManagerStats
	mu             sync.RWMutex
	updateChan     chan *StrategyResult
	closeChan      chan struct{}
	googleRanges   []*net.IPNet
	cidrIndex      map[byte][]*net.IPNet
	rangesMu       sync.RWMutex
	lastUpdateTime time.Time
	updateErr      error

	hostnameRules *hostnameRules

	testOverrides   map[string]int
	testOverridesMu sync.RWMutex

	// statsMap хранит изменяемую статистику отдельно от конфига Strategy.
	// Ключ совпадает с Strategy.ID. Запись создаётся в AddStrategy.
	statsMap map[int]*strategyRuntimeStats
	statsMu  sync.RWMutex
}

// ManagerStats статистика менеджера
type ManagerStats struct {
	TotalStrategies    int
	ActiveStrategies   int
	SuccessfulAttempts uint64
	FailedAttempts     uint64
	LastSwitchTime     time.Time
}

// NewManager создает новый менеджер стратегий
func NewManager() *Manager {
	m := &Manager{
		strategies:    make(map[int]*Strategy),
		filters:       make(map[string]*StrategyFilter),
		updateChan:    make(chan *StrategyResult, 1000),
		closeChan:     make(chan struct{}),
		googleRanges:  make([]*net.IPNet, 0),
		cidrIndex:     make(map[byte][]*net.IPNet),
		testOverrides: make(map[string]int),
		statsMap:      make(map[int]*strategyRuntimeStats),
	}

	// FIX #2: hostnameRules — pointer, необходима явная инициализация.
	m.hostnameRules = &hostnameRules{
		byExact: make(map[string]int),
	}

	m.loadDefaultStrategies()

	go m.processResults()

	go m.startGoogleIPUpdater()

	// FIX #6: первичная загрузка в горутине, не блокируем конструктор.
	// Было: m.updateGoogleIPRanges() синхронно — 3 retry × 20s = до 60с блокировки.
	// Fallback-список применяется немедленно если HTTP недоступен.
	go m.updateGoogleIPRanges()

	return m
}

// startGoogleIPUpdater запускает периодическое обновление диапазонов Google
func (m *Manager) startGoogleIPUpdater() {
	ticker := time.NewTicker(12 * time.Hour) // каждые 12 часов — достаточно
	defer ticker.Stop()

	for {
		select {
		case <-m.closeChan:
			return
		case <-ticker.C:
			m.updateGoogleIPRanges()
		}
	}
}

// fallbackRanges используется когда онлайн-источники недоступны
var fallbackRanges = []string{
	// Минимальный набор для YouTube (актуально на 2026)
	"8.8.4.0/24",
	"8.8.8.0/24",
	"8.34.208.0/20",
	"8.35.192.0/20",
	"23.236.48.0/20",
	"23.251.128.0/19",
	"34.0.0.0/15",
	"34.2.0.0/16",
	"34.3.0.0/23",
	"34.4.0.0/14",
	"34.8.0.0/13",
	"34.16.0.0/12",
	"34.32.0.0/11",
	"34.64.0.0/10",
	"34.128.0.0/10",
	"35.184.0.0/13",
	"35.192.0.0/14",
	"35.196.0.0/15",
	"35.198.0.0/16",
	"35.199.0.0/17",
	"35.199.128.0/18",
	"35.200.0.0/13",
	"35.208.0.0/12",
	"35.224.0.0/12",
	"35.240.0.0/13",
	"64.15.112.0/20",
	"64.233.112.0/20",
	"64.233.160.0/19",
	"66.102.0.0/20",
	"66.249.64.0/19",
	"70.32.112.0/20",
	"72.14.192.0/18",
	"74.114.24.0/21",
	"74.125.0.0/16",
	"104.154.0.0/15",
	"104.196.0.0/14",
	"108.59.80.0/20",
	"108.170.192.0/18",
	"108.177.0.0/17",
	"130.211.0.0/16",
	"142.250.0.0/15",
	"146.148.0.0/17",
	"162.216.148.0/22",
	"162.222.176.0/21",
	"172.110.32.0/21",
	"172.217.0.0/16",
	"172.253.0.0/16",
	"173.194.0.0/16",
	"192.158.28.0/22",
	"192.178.0.0/15",
	"199.36.154.0/23",
	"199.36.156.0/24",
	"199.192.112.0/22",
	"199.223.232.0/21",
	"207.223.160.0/20",
	"208.65.152.0/22",
	"208.68.108.0/22",
	"208.81.188.0/22",
	"208.117.224.0/19",
	"209.85.128.0/17",
	"216.58.192.0/19",
	"216.73.80.0/20",
	"216.239.32.0/19",
}

// updateGoogleIPRanges — полный rewrite с диагностикой и retry
func (m *Manager) updateGoogleIPRanges() {
	urls := []string{
		"https://www.gstatic.com/ipranges/goog.json",
		"https://www.gstatic.com/ipranges/cloud.json",
	}

	var allPrefixes []string

	for _, url := range urls {
		log.Printf("[GoogleIP] Attempting to download: %s", url)

		for attempt := 1; attempt <= 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				cancel()
				log.Printf("[GoogleIP] Failed to create request (attempt %d): %v", attempt, err)
				time.Sleep(time.Second * time.Duration(attempt))
				continue
			}

			req.Header.Set("User-Agent", "ByPass/1.0 (Google IP Updater)")

			client := &http.Client{Timeout: 15 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				log.Printf("[GoogleIP] Download failed (attempt %d, url=%s): %v", attempt, url, err)
				time.Sleep(time.Second * time.Duration(attempt))
				continue
			}

			log.Printf("[GoogleIP] Response status: %s", resp.Status)

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				cancel()
				log.Printf("[GoogleIP] Bad status %d from %s", resp.StatusCode, url)
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			cancel()
			if err != nil {
				log.Printf("[GoogleIP] Failed to read body from %s: %v", url, err)
				continue
			}

			log.Printf("[GoogleIP] Downloaded %d bytes from %s", len(body), url)

			var list struct {
				SyncToken string `json:"syncToken"`
				Prefixes  []struct {
					IPv4Prefix string `json:"ipv4Prefix"`
				} `json:"prefixes"`
			}

			if err := json.Unmarshal(body, &list); err != nil {
				log.Printf("[GoogleIP] JSON parse error from %s: %v", url, err)
				continue
			}

			for _, p := range list.Prefixes {
				if p.IPv4Prefix != "" {
					allPrefixes = append(allPrefixes, p.IPv4Prefix)
				}
			}

			log.Printf("[GoogleIP] Parsed %d IPv4 prefixes from %s", len(list.Prefixes), url)
			break // успех — выходим из retry
		}
	}

	// Если ничего не скачали — fallback
	if len(allPrefixes) == 0 {
		log.Printf("[GoogleIP] No prefixes loaded from online sources — using fallback list")
		allPrefixes = fallbackRanges
	}

	newRanges := make([]*net.IPNet, 0, len(allPrefixes))
	newIndex := make(map[byte][]*net.IPNet)
	for _, cidr := range allPrefixes {
		_, netw, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[GoogleIP] Invalid CIDR %q: %v", cidr, err)
			continue
		}
		newRanges = append(newRanges, netw)
		if ip4 := netw.IP.To4(); ip4 != nil {
			octet := ip4[0]
			newIndex[octet] = append(newIndex[octet], netw)
		}
	}

	m.rangesMu.Lock()
	m.googleRanges = newRanges
	m.cidrIndex = newIndex
	m.lastUpdateTime = time.Now()
	m.updateErr = nil
	m.rangesMu.Unlock()

	usingFallback := len(allPrefixes) == len(fallbackRanges)
	log.Printf("[GoogleIP] Loaded %d IPv4 ranges (fallback=%t)", len(newRanges), usingFallback)
}

// isGoogleIP проверяет, входит ли IP в диапазоны Google/YouTube.
// Использует cidrIndex для отсева по первому октету — вместо O(n) по всему списку
// делает O(k) где k — количество сетей с данным первым октетом (обычно 1-5).
func (m *Manager) isGoogleIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false // IPv6 не поддерживаем
	}

	m.rangesMu.RLock()
	defer m.rangesMu.RUnlock()

	if len(m.cidrIndex) == 0 {
		return false
	}

	candidates, ok := m.cidrIndex[ip4[0]]
	if !ok {
		return false
	}

	for _, cidr := range candidates {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Stop останавливает менеджер
func (m *Manager) Stop() {
	close(m.closeChan)
}

// AddStrategy добавляет стратегию.
// FIX auto-ID: ищем первый свободный ID вместо len()+1 — устраняет коллизии
// при наличии стратегий с явными ID (например 1,2,3,60 → len=4, но ID 4 может быть занят).
func (m *Manager) AddStrategy(strategy *Strategy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strategy.ID == 0 {
		for id := 1; ; id++ {
			if _, exists := m.strategies[id]; !exists {
				strategy.ID = id
				break
			}
		}
	}

	if _, exists := m.strategies[strategy.ID]; exists {
		return fmt.Errorf("strategy with ID %d already exists", strategy.ID)
	}

	m.strategies[strategy.ID] = strategy
	m.stats.TotalStrategies++

	// Инициализируем запись в statsMap — изолируем изменяемую статистику
	// от иммутабельного конфига Strategy (#3 в review).
	m.statsMu.Lock()
	m.statsMap[strategy.ID] = &strategyRuntimeStats{}
	m.statsMu.Unlock()

	return nil
}

// GetStrategy возвращает стратегию по ID.
// Возвращает (nil, false) если стратегия не найдена.
func (m *Manager) GetStrategy(id int) (*Strategy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	strat, exists := m.strategies[id]
	return strat, exists
}

// SetTestOverride временно форсирует стратегию strategyID для hostname.
// Используется Discovery: вызвать перед тестовым соединением, ClearTestOverride — после.
func (m *Manager) SetTestOverride(hostname string, strategyID int) {
	m.testOverridesMu.Lock()
	m.testOverrides[strings.ToLower(hostname)] = strategyID
	m.testOverridesMu.Unlock()
}

// ClearTestOverride снимает тестовый override для hostname.
func (m *Manager) ClearTestOverride(hostname string) {
	m.testOverridesMu.Lock()
	delete(m.testOverrides, strings.ToLower(hostname))
	m.testOverridesMu.Unlock()
}

// SetTestOverrideByIP форсирует стратегию для конкретного IP.
// Используется Discovery для QUIC-тестов: QUIC-пакеты не содержат SNI.
// Ключ: "ip:<addr>" — не конфликтует с hostname-ключами.
func (m *Manager) SetTestOverrideByIP(ip string, strategyID int) {
	m.testOverridesMu.Lock()
	m.testOverrides["ip:"+ip] = strategyID
	m.testOverridesMu.Unlock()
}

// ClearTestOverrideByIP снимает IP-based override.
func (m *Manager) ClearTestOverrideByIP(ip string) {
	m.testOverridesMu.Lock()
	delete(m.testOverrides, "ip:"+ip)
	m.testOverridesMu.Unlock()
}

// FIX #1: переименовали package-level var с hostnameRules → builtinHostnameMappings,
// чтобы устранить конфликт имён с типом hostnameRules (hostname_rules.go).
// Было: var hostnameRules = []struct{...}  ← compile error: redeclared in this block.
//
// builtinHostnameMappings — таблица «содержит подстроку → nameHint для стратегии».
// Используется в SelectStrategy шаг 2 (после hostnameRules и testOverrides).
var builtinHostnameMappings = []struct {
	hostnameContains string // подстрока в hostname (lowercase)
	stratNameHint    string // подстрока в имени стратегии
}{
	{"youtube.com", "youtube"},
	{"googlevideo.com", "youtube"},
	{"googleapis.com", "youtube"},
	{"gstatic.com", "youtube"},
	{"ggpht.com", "youtube"},
	{"ytimg.com", "youtube"},
	{"youtu.be", "youtube"},
	{"googleusercontent.com", "youtube"},
	{"google.com", "youtube"},
	{"gmail.com", "youtube"},
	{"discord.com", "discord"},
	{"discord.gg", "discord"},
	{"discordapp.com", "discord"},
	{"discordapp.net", "discord"},
	{"discord.media", "discord"},
	{"telegram.org", "telegram"},
	{"telegram.me", "telegram"},
	{".t.me", "telegram"},
}

// protocolMatches проверяет применимость стратегии к протоколу/порту.
func protocolMatches(s *Strategy, protocol string, port int) bool {
	switch protocol {
	case "tcp":
		return s.ApplyToTLS || s.ApplyToHTTP
	case "udp":
		return port == 443 && (s.ApplyToQUIC || s.FakeQUICFile != "")
	}
	return false
}

// isPassthrough возвращает true если стратегия не делает реальных модификаций.
func isPassthrough(s *Strategy) bool {
	return s.SplitMode == SplitNone &&
		s.DisorderMode == DisorderNone &&
		s.Fooling == 0 &&
		!s.SynData &&
		!s.MultiDisorder &&
		!s.FakedSplit &&
		s.SeqOvlLen == 0 &&
		len(s.FakeTLSFiles) == 0 &&
		s.FakeQUICFile == ""
}

// selectByNameHint ищет стратегию с наименьшим Priority среди тех, чьё имя
// содержит nameHint и чей протокол соответствует protocol/port.
//
// FIX: при одинаковом Priority выбираем стратегию с меньшим ID.
// Итерация по Go map нестабильна — без тай-брейкера разные воркеры получают
// разные стратегии для одного IP → ipcache осциллирует (видно в логах: 20↔25).
//
// Вызывается под m.mu.RLock.
func (m *Manager) selectByNameHint(nameHint, protocol string, port int) *Strategy {
	var best *Strategy
	bestPri := int(^uint(0) >> 1)
	for _, s := range m.strategies {
		if isPassthrough(s) {
			continue
		}
		if !strings.Contains(s.Name, nameHint) {
			continue
		}
		if !protocolMatches(s, protocol, port) {
			continue
		}
		// FIX: тай-брейкер по ID — детерминированный выбор при равном приоритете
		if best == nil || s.Priority < bestPri || (s.Priority == bestPri && s.ID < best.ID) {
			best = s
			bestPri = s.Priority
		}
	}
	return best
}

// findByName ищет стратегию по подстроке имени без фильтрации по протоколу.
// Используется hostname_rules.go при компиляции правил (SetHostnameRules),
// когда protocol/port ещё неизвестны.
//
// FIX: тай-брейкер по ID.
// Вызывается под m.mu.RLock.
func (m *Manager) findByName(nameHint string) *Strategy {
	var best *Strategy
	bestPri := int(^uint(0) >> 1)
	for _, s := range m.strategies {
		if isPassthrough(s) {
			continue
		}
		if !strings.Contains(s.Name, nameHint) {
			continue
		}
		// FIX: тай-брейкер по ID — детерминированный выбор при равном приоритете
		if best == nil || s.Priority < bestPri || (s.Priority == bestPri && s.ID < best.ID) {
			best = s
			bestPri = s.Priority
		}
	}
	return best
}

// bestForProtocol выбирает лучшую (наименьший Priority) не-passthrough стратегию
// для данного протокола.
//
// FIX: тай-брейкер по ID.
// Вызывается под m.mu.RLock.
func (m *Manager) bestForProtocol(protocol string, port int) *Strategy {
	var best *Strategy
	bestPri := int(^uint(0) >> 1)
	for _, s := range m.strategies {
		if isPassthrough(s) {
			continue
		}
		if !protocolMatches(s, protocol, port) {
			continue
		}
		// FIX: тай-брейкер по ID — детерминированный выбор при равном приоритете
		if best == nil || s.Priority < bestPri || (s.Priority == bestPri && s.ID < best.ID) {
			best = s
			bestPri = s.Priority
		}
	}
	return best
}

// SelectStrategy выбирает стратегию для пакета.
//
// Порядок приоритетов:
//  0. HostnameRules (SetHostnameRules) — статические правила, абсолютный приоритет
//     FIX #4: для QUIC (hostname="") ищем hostname через builtinHostnameMappings по IP
//  1. testOverrides — форсирование от Discovery (hostname или IP)
//  2. Google IP диапазоны → стратегия по nameHint
//     FIX #2: hint для UDP = "youtube" (было "quic" — ни одна стратегия не совпадала)
//  3. builtinHostnameMappings — hostname содержит известную подстроку
//  4. Fallback: лучшая по Priority не-passthrough стратегия для данного протокола
func (m *Manager) SelectStrategy(ip, hostname string, port int, protocol string) *Strategy {
	// ── 0. Hostname Rules (абсолютный приоритет) ─────────────────────────────
	if hostname != "" {
		if s := m.hostnameRuleStrategy(hostname); s != nil {
			return s
		}
	} else if protocol == "udp" {
		// FIX #4: QUIC-пакеты не содержат SNI — hostname пуст.
		// Пробуем найти hostname через builtinHostnameMappings по IP
		// (Google IP → "youtube.com"), затем проверяем HostnameRules.
		// Без этого HostnameRules игнорировались для всего QUIC-трафика.
		if inferredHostname := m.inferHostnameForIP(ip); inferredHostname != "" {
			if s := m.hostnameRuleStrategy(inferredHostname); s != nil {
				return s
			}
		}
	}

	// ── 1. Test override — форсированная стратегия от Discovery ──────────────
	m.testOverridesMu.RLock()
	var overrideStratID int
	var hasOverride bool
	if hostname != "" {
		overrideStratID, hasOverride = m.testOverrides[strings.ToLower(hostname)]
	} else {
		overrideStratID, hasOverride = m.testOverrides["ip:"+ip]
	}
	m.testOverridesMu.RUnlock()

	if hasOverride {
		m.mu.RLock()
		s, exists := m.strategies[overrideStratID]
		m.mu.RUnlock()
		if exists {
			label := "IP='" + ip + "'"
			if hostname != "" {
				label = "hostname='" + strings.ToLower(hostname) + "'"
			}
			log.Printf("[SELECT] TestOverride %s → strategy %d (%s)", label, s.ID, s.Name)
			return s
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// ── 2. Google IP ──────────────────────────────────────────────────────────
	if m.isGoogleIP(ip) {
		// FIX #2: для UDP hint был "quic" — ни одна стратегия не содержит "quic" в имени.
		// "youtube" совпадает с "yt-syndata-2026" и "youtube-2026".
		hint := "youtube"
		if s := m.selectByNameHint(hint, protocol, port); s != nil {
			return s
		}
		if s := m.bestForProtocol(protocol, port); s != nil {
			return s
		}
	}

	// ── 3. builtinHostnameMappings ────────────────────────────────────────────
	if hostname != "" {
		lower := strings.ToLower(hostname)
		for _, rule := range builtinHostnameMappings {
			if strings.Contains(lower, rule.hostnameContains) {
				if s := m.selectByNameHint(rule.stratNameHint, protocol, port); s != nil {
					return s
				}
			}
		}
	}

	// ── 4. Fallback ───────────────────────────────────────────────────────────
	if s := m.bestForProtocol(protocol, port); s != nil {
		log.Printf("[SELECT] Fallback → strategy %d (%s) priority=%d", s.ID, s.Name, s.Priority)
		return s
	}

	log.Printf("[SELECT] No strategy for %s:%d (hostname='%s')", ip, port, hostname)
	return nil
}

// inferHostnameForIP возвращает каноническое hostname для IP по builtinHostnameMappings.
// Используется для QUIC-пакетов где SNI отсутствует: Google IP → "youtube.com".
// Не выполняет reverse DNS — только проверяет Google-диапазоны.
func (m *Manager) inferHostnameForIP(ip string) string {
	if m.isGoogleIP(ip) {
		return "youtube.com"
	}
	return ""
}

// SetDefault устанавливает стратегию по умолчанию
func (m *Manager) SetDefault(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.strategies[id]; !exists {
		return fmt.Errorf("strategy %d not found", id)
	}

	m.defaultID = id
	return nil
}

// SetActive устанавливает активную стратегию
func (m *Manager) SetActive(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.strategies[id]; !exists {
		return fmt.Errorf("strategy %d not found", id)
	}

	m.activeID = id
	m.stats.LastSwitchTime = time.Now()

	return nil
}

// GetActive возвращает активную стратегию
func (m *Manager) GetActive() *Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeID > 0 {
		return m.strategies[m.activeID]
	}
	return nil
}

// UpdateStrategy обновляет статистику стратегии.
//
// FIX #3: пишем в statsMap[id] а не в Strategy напрямую.
// Strategy-указатель после AddStrategy иммутабелен — SelectStrategy может
// возвращать его вызывающим горутинам без риска data race.
//
// FIX lock order: ранее m.mu.Lock() захватывался ВНУТРИ st.mu.Lock() →
// потенциальный дедлок если другая горутина держит m.mu и ждёт st.mu.
// Теперь: сначала обновляем st под st.mu, затем глобальный счётчик под m.mu.
// Эти два обновления некритичны к атомарности — небольшая рассинхронизация счётчиков
// допустима для статистики.
func (m *Manager) UpdateStrategy(id int, success bool, responseTime time.Duration) {
	m.mu.RLock()
	_, exists := m.strategies[id]
	m.mu.RUnlock()
	if !exists {
		return
	}

	m.statsMu.RLock()
	st, ok := m.statsMap[id]
	m.statsMu.RUnlock()
	if !ok {
		return
	}

	// Обновляем статистику стратегии под st.mu
	st.mu.Lock()
	st.lastUsed = time.Now()
	if success {
		st.successCount++
		if st.avgResponseMs == 0 {
			st.avgResponseMs = responseTime.Milliseconds()
		} else {
			st.avgResponseMs = (st.avgResponseMs*int64(st.successCount-1) +
				responseTime.Milliseconds()) / int64(st.successCount)
		}
	} else {
		st.failCount++
	}
	st.mu.Unlock()

	// FIX: обновляем глобальные счётчики ПОСЛЕ release st.mu — устраняем lock order violation.
	// Было: m.mu.Lock() внутри st.mu.Lock() → потенциальный дедлок.
	m.mu.Lock()
	if success {
		m.stats.SuccessfulAttempts++
	} else {
		m.stats.FailedAttempts++
	}
	m.mu.Unlock()
}

// GetStrategyStats возвращает снимок статистики для стратегии.
// Отдельно от Strategy чтобы не раскрывать изменяемые поля напрямую.
func (m *Manager) GetStrategyStats(id int) (successCount, failCount int, avgResponseMs int64, lastUsed time.Time, ok bool) {
	m.statsMu.RLock()
	st, exists := m.statsMap[id]
	m.statsMu.RUnlock()
	if !exists {
		return 0, 0, 0, time.Time{}, false
	}
	st.mu.Lock()
	successCount = st.successCount
	failCount = st.failCount
	avgResponseMs = st.avgResponseMs
	lastUsed = st.lastUsed
	st.mu.Unlock()
	return successCount, failCount, avgResponseMs, lastUsed, true
}

// ReportResult сообщает о результате применения стратегии
func (m *Manager) ReportResult(result *StrategyResult) {
	select {
	case m.updateChan <- result:
	default:
		// Канал переполнен, пропускаем
	}
}

// processResults обрабатывает результаты асинхронно
func (m *Manager) processResults() {
	for {
		select {
		case <-m.closeChan:
			for len(m.updateChan) > 0 {
				<-m.updateChan
			}
			return
		case result := <-m.updateChan:
			m.UpdateStrategy(result.StrategyID, result.Success, result.ResponseTime)
		}
	}
}

// ListStrategies возвращает список всех стратегий, отсортированный по приоритету
func (m *Manager) ListStrategies() []*Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	strategies := make([]*Strategy, 0, len(m.strategies))
	for _, strat := range m.strategies {
		strategies = append(strategies, strat)
	}

	sort.Slice(strategies, func(i, j int) bool {
		return strategies[i].Priority < strategies[j].Priority
	})

	return strategies
}

// SaveToFile сохраняет стратегии в файл
func (m *Manager) SaveToFile(filename string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.strategies, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadFromFile загружает стратегии из файла.
// FIX #5: не заменяет m.strategies целиком — добавляет/обновляет стратегии из файла,
// сохраняя встроенные стратегии из profiles.go.
// Было: m.strategies = make(map[int]*Strategy) → встроенные стратегии уничтожались.
func (m *Manager) LoadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Пробуем загрузить как массив (новый формат)
	var strategiesArray []*Strategy
	if err := json.Unmarshal(data, &strategiesArray); err == nil {
		m.mu.Lock()
		defer m.mu.Unlock()

		loaded := 0
		for _, s := range strategiesArray {
			if s.ID == 0 {
				continue
			}
			m.strategies[s.ID] = s
			m.statsMu.Lock()
			if _, exists := m.statsMap[s.ID]; !exists {
				m.statsMap[s.ID] = &strategyRuntimeStats{}
			}
			m.statsMu.Unlock()
			loaded++
		}
		m.stats.TotalStrategies = len(m.strategies)
		log.Printf("[LoadFromFile] Merged %d strategies from %s (total: %d)", loaded, filename, len(m.strategies))
		return nil
	}

	// Если не получилось как массив, пробуем как map (старый формат)
	var strategiesMap map[int]*Strategy
	if err := json.Unmarshal(data, &strategiesMap); err != nil {
		return fmt.Errorf("failed to parse strategies: %v (tried array and map)", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	loaded := 0
	for id, s := range strategiesMap {
		m.strategies[id] = s
		m.statsMu.Lock()
		if _, exists := m.statsMap[id]; !exists {
			m.statsMap[id] = &strategyRuntimeStats{}
		}
		m.statsMu.Unlock()
		loaded++
	}
	m.stats.TotalStrategies = len(m.strategies)
	log.Printf("[LoadFromFile] Merged %d strategies from %s (total: %d)", loaded, filename, len(m.strategies))
	return nil
}

// GetStats возвращает статистику
func (m *Manager) GetStats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	stats.TotalStrategies = len(m.strategies)
	stats.ActiveStrategies = 1

	return stats
}

// loadDefaultStrategies is implemented as a method in profiles.go
