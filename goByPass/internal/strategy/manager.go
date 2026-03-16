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
	"path/filepath"
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
	stopOnce       sync.Once

	hostnameRules *hostnameRules

	testOverrides   map[string]int
	testOverridesMu sync.RWMutex

	discoveryRunning bool       // защищает от глобального ломания трафика
	updateMu         sync.Mutex // предотвращает параллельные обновления Google IP

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
		strategies:       make(map[int]*Strategy),
		filters:          make(map[string]*StrategyFilter),
		updateChan:       make(chan *StrategyResult, 1000),
		closeChan:        make(chan struct{}),
		googleRanges:     make([]*net.IPNet, 0),
		cidrIndex:        make(map[byte][]*net.IPNet),
		testOverrides:    make(map[string]int),
		statsMap:         make(map[int]*strategyRuntimeStats),
		discoveryRunning: false,
	}

	// FIX #2: hostnameRules — pointer, необходима явная инициализация.
	m.hostnameRules = &hostnameRules{
		byExact: make(map[string]int),
	}

	m.loadDefaultStrategies()

	m.seedGoogleFallbackRanges()

	go m.processResults()
	go m.startGoogleIPUpdater()
	go m.updateGoogleIPRanges()

	return m
}

func (m *Manager) seedGoogleFallbackRanges() {
	newRanges := make([]*net.IPNet, 0, len(fallbackRanges))
	newIndex := make(map[byte][]*net.IPNet)

	for _, cidr := range fallbackRanges {
		_, netw, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[GoogleIP] Invalid fallback CIDR %q: %v", cidr, err)
			continue
		}
		newRanges = append(newRanges, netw)
		if ip4 := netw.IP.To4(); ip4 != nil {
			newIndex[ip4[0]] = append(newIndex[ip4[0]], netw)
		}
	}

	m.rangesMu.Lock()
	if len(m.googleRanges) == 0 && len(m.cidrIndex) == 0 {
		m.googleRanges = newRanges
		m.cidrIndex = newIndex
		m.lastUpdateTime = time.Now()
		log.Printf("[GoogleIP] Seeded %d fallback IPv4 ranges before async update", len(newRanges))
	}
	m.rangesMu.Unlock()
}

// SetDiscoveryRunning вызывается из Discovery.Start/Stop
func (m *Manager) SetDiscoveryRunning(running bool) {
	m.mu.Lock()
	m.discoveryRunning = running
	m.mu.Unlock()
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
	m.updateMu.Lock()
	defer m.updateMu.Unlock()

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
	m.stopOnce.Do(func() {
		close(m.closeChan)
	})
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

// builtinHostnameMappings — узкие встроенные правила для известных сервисов.
// ВАЖНО:
//   - не тащим сюда общий Google (google.com, gmail.com, gstatic.com и т.п.),
//     чтобы не применять YouTube-bypass к обычным сайтам;
//   - используем набор hints, а не один "youtube", чтобы находить стратегии
//     вроде "yt-syndata-2026" и "quic-fake-6".
var builtinHostnameMappings = []struct {
	hostnameContains string
	strategyHints    []string
}{
	// YouTube / CDN only
	{"youtube.com", []string{"youtube-safe", "youtube", "quic-fake", "yt-syndata"}},
	{"youtube-nocookie.com", []string{"youtube-safe", "youtube", "quic-fake", "yt-syndata"}},
	{"googlevideo.com", []string{"youtube-safe", "quic-fake", "youtube", "yt-syndata"}},
	{"youtubei.googleapis.com", []string{"youtube-safe", "youtube", "quic-fake", "yt-syndata"}},
	{"ytimg.com", []string{"youtube-safe", "youtube"}},
	{"ggpht.com", []string{"youtube-safe", "youtube"}},
	{"gvt1.com", []string{"youtube-safe", "quic-fake", "youtube", "yt-syndata"}},
	{"gvt2.com", []string{"youtube-safe", "quic-fake", "youtube", "yt-syndata"}},
	{"youtu.be", []string{"youtube-safe", "youtube"}},

	// Discord
	{"discord.com", []string{"discord"}},
	{"discord.gg", []string{"discord"}},
	{"discordapp.com", []string{"discord"}},
	{"discordapp.net", []string{"discord"}},
	{"discord.media", []string{"discord"}},

	// Telegram
	{"telegram.org", []string{"telegram-safe", "telegram"}},
	{"telegram.me", []string{"telegram-safe", "telegram"}},
	{".t.me", []string{"telegram-safe", "telegram"}},
}

// protocolMatches проверяет применимость стратегии к протоколу/порту.
func protocolMatches(s *Strategy, protocol string, port int) bool {
	if s == nil {
		return false
	}

	switch protocol {
	case "tcp":
		// AnyProtocol разрешаем для TCP, но не используем это как "магическое совпадение"
		// для всех UDP-профилей.
		return s.AnyProtocol ||
			s.ApplyToTLS ||
			s.ApplyToHTTP ||
			s.FakeHTTPFile != "" ||
			s.HostFakeSplit ||
			s.TLSRecordSplit
	case "udp":
		// QUIC/UDP443 или неизвестный UDP fake (игровые профили).
		if s.AnyProtocol && (s.FakeUnknownUDPFile != "" || len(s.FakeUnknownUDPFileData) > 0) {
			return true
		}
		if port == 443 && (s.ApplyToQUIC || s.FakeQUICFile != "" || len(s.FakeQUICFileData) > 0) {
			return true
		}
		return s.FakeUnknownUDPFile != "" || len(s.FakeUnknownUDPFileData) > 0
	}

	return false
}

// isPassthrough возвращает true если стратегия не делает реальных модификаций.
func isPassthrough(s *Strategy) bool {
	if s == nil {
		return true
	}

	return s.SplitMode == SplitNone &&
		s.DisorderMode == DisorderNone &&
		s.Fooling == 0 &&
		!s.SynData &&
		!s.MultiDisorder &&
		!s.FakedSplit &&
		s.SeqOvlLen == 0 &&
		len(s.FakeTLSFiles) == 0 &&
		s.FakeHTTPFile == "" &&
		s.FakeQUICFile == "" &&
		s.FakeUnknownUDPFile == "" &&
		!s.HostFakeSplit &&
		s.HTTPModMode == HTTPModNone &&
		!s.HostCase &&
		!s.ExtraSpace &&
		!s.DotAtEnd &&
		!s.TLSRecordSplit &&
		!s.IPIDZero
}

// selectByHintOrder ищет стратегии в заданном порядке hints.
// Для каждого hint выбирается лучший кандидат по Priority/ID,
// но между hints порядок ЖЁСТКИЙ: первый найденный hint выигрывает.
func (m *Manager) selectByHintOrder(hints []string, protocol string, port int) *Strategy {
	for _, hint := range hints {
		if s := m.selectByHints([]string{hint}, protocol, port); s != nil {
			return s
		}
	}
	return nil
}

// passthroughStrategy возвращает strategy 1.
// Вызывается под m.mu.RLock.
func (m *Manager) passthroughStrategy() *Strategy {
	return m.strategies[1]
}

// activeStrategyForKnownService возвращает текущую active-стратегию,
// если она существует, не является passthrough и подходит под protocol/port.
//
// ВАЖНО: используем activeID только для уже распознанных сервисов
// (builtin hostname mapping / Google IP special-case), а не как глобальный fallback.
// Так discovery реально начинает влиять на боевой трафик,
// но direct-by-default для неизвестных сайтов сохраняется.
func (m *Manager) activeStrategyForKnownService(protocol string, port int) *Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeID <= 0 {
		return nil
	}

	s := m.strategies[m.activeID]
	if s == nil {
		return nil
	}
	if isPassthrough(s) {
		return nil
	}
	if !protocolMatches(s, protocol, port) {
		return nil
	}

	return s
}

// selectByHints ищет лучшую (минимальный Priority, потом минимальный ID)
// НЕ-passthrough стратегию, имя которой содержит любой из hints и которая
// подходит для protocol/port.
//
// Вызывается под m.mu.RLock.
func (m *Manager) selectByHints(hints []string, protocol string, port int) *Strategy {
	if len(hints) == 0 {
		return nil
	}

	var best *Strategy
	bestPri := int(^uint(0) >> 1)

	for _, s := range m.strategies {
		if isPassthrough(s) {
			continue
		}
		if !protocolMatches(s, protocol, port) {
			continue
		}

		name := strings.ToLower(s.Name)
		matched := false
		for _, hint := range hints {
			hint = strings.ToLower(strings.TrimSpace(hint))
			if hint != "" && strings.Contains(name, hint) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		if best == nil || s.Priority < bestPri || (s.Priority == bestPri && s.ID < best.ID) {
			best = s
			bestPri = s.Priority
		}
	}
	return best
}

// selectByNameHint оставляем как thin-wrapper для совместимости.
func (m *Manager) selectByNameHint(nameHint, protocol string, port int) *Strategy {
	return m.selectByHints([]string{nameHint}, protocol, port)
}

// findByName ищет стратегию по подстроке имени без фильтрации по протоколу.
// Используется hostname_rules.go при компиляции правил (SetHostnameRules),
// когда protocol/port ещё неизвестны.
//
// В отличие от selectByHints, passthrough тут НЕ исключаем:
// это позволяет явно задать hostname rule на strategy 1.
//
// Вызывается под m.mu.RLock.
func (m *Manager) findByName(nameHint string) *Strategy {
	hint := strings.ToLower(strings.TrimSpace(nameHint))
	if hint == "" {
		return nil
	}

	var best *Strategy
	bestPri := int(^uint(0) >> 1)

	for _, s := range m.strategies {
		if !strings.Contains(strings.ToLower(s.Name), hint) {
			continue
		}
		if best == nil || s.Priority < bestPri || (s.Priority == bestPri && s.ID < best.ID) {
			best = s
			bestPri = s.Priority
		}
	}
	return best
}

// bestForProtocol выбирает лучшую (наименьший Priority) не-passthrough стратегию
// для данного протокола.
// Оставлен как утилита, но SelectStrategy для неизвестных сайтов его больше
// не использует — unknown host должен идти direct, а не в forced bypass.
//
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
		if best == nil || s.Priority < bestPri || (s.Priority == bestPri && s.ID < best.ID) {
			best = s
			bestPri = s.Priority
		}
	}
	return best
}

// SelectStrategy выбирает стратегию для пакета.
//
// Порядок:
//  0. Discovery override — абсолютный приоритет только во время discovery
//  1. HostnameRules — абсолютный приоритет среди постоянных правил
//  2. Обычный test override (если используется вне discovery)
//  3. builtinHostnameMappings — для известных сервисов;
//     сначала пробуем active strategy, затем встроенные hints
//  4. Google IP special-case для hostname-less QUIC/TLS YouTube CDN;
//     сначала active strategy, затем YouTube/QUIC hints
//  5. Всё неизвестное — passthrough (strategy 1)
//
// Идея: direct-by-default.
// Неизвестный сайт НЕ должен получать light/medium/hard автоматически.
func (m *Manager) SelectStrategy(ip, hostname string, port int, protocol string) *Strategy {
	normalizedHostname := strings.ToLower(strings.TrimSuffix(hostname, "."))

	// 0. Discovery override — абсолютный приоритет только во время discovery
	if m.isDiscoveryRunning() {
		m.testOverridesMu.RLock()
		var overrideStratID int
		var hasOverride bool

		if normalizedHostname != "" {
			overrideStratID, hasOverride = m.testOverrides[normalizedHostname]
		} else if protocol == "udp" {
			overrideStratID, hasOverride = m.testOverrides["ip:"+ip]
		}

		m.testOverridesMu.RUnlock()

		if hasOverride {
			m.mu.RLock()
			s := m.strategies[overrideStratID]
			m.mu.RUnlock()
			if s != nil {
				return s
			}
		}
	}

	// 1. Hostname rules
	if normalizedHostname != "" {
		if s := m.hostnameRuleStrategy(normalizedHostname); s != nil {
			return s
		}
	} else if protocol == "udp" {
		// QUIC без SNI: пробуем inferred hostname только для поддержки
		// статических HostnameRules.
		if inferred := m.inferHostnameForIP(ip); inferred != "" {
			if s := m.hostnameRuleStrategy(inferred); s != nil {
				return s
			}
		}
	}

	// 2. Обычный override вне discovery
	m.testOverridesMu.RLock()
	var overrideStratID int
	var hasOverride bool

	if normalizedHostname != "" {
		overrideStratID, hasOverride = m.testOverrides[normalizedHostname]
	} else if protocol == "udp" {
		overrideStratID, hasOverride = m.testOverrides["ip:"+ip]
	}

	m.testOverridesMu.RUnlock()

	if hasOverride {
		m.mu.RLock()
		s, exists := m.strategies[overrideStratID]
		m.mu.RUnlock()
		if exists {
			return s
		}
	}

	// 3. builtinHostnameMappings — теперь реально используются
	if normalizedHostname != "" {
		for _, mapping := range builtinHostnameMappings {
			if !strings.Contains(normalizedHostname, mapping.hostnameContains) {
				continue
			}

			// Если discovery уже выбрал лучшую стратегию — используем её
			// для распознанного сервиса.
			if s := m.activeStrategyForKnownService(protocol, port); s != nil {
				log.Printf("[SELECT] Active strategy for known service hostname=%q ip=%s:%d → strategy %d (%s)",
					normalizedHostname, ip, port, s.ID, s.Name)
				return s
			}

			// Иначе fallback на встроенные hints.
			if s := m.selectByHintOrder(mapping.strategyHints, protocol, port); s != nil {
				log.Printf("[SELECT] Builtin hostname mapping hostname=%q ip=%s:%d → strategy %d (%s)",
					normalizedHostname, ip, port, s.ID, s.Name)
				return s
			}

			// hostname распознан, но подходящей non-passthrough стратегии нет.
			break
		}
	}

	// 4. Google IP special-case
	// ОСТАВЛЯЕМ ТОЛЬКО ДЛЯ UDP/QUIC.
	//
	// Для TCP: bare Google IP слишком часто относится не только к YouTube,
	// но и к shared Google frontends / API / auth / вспомогательным сервисам.
	// Агрессивный fallback "любой Google TCP:443 -> YouTube strategy"
	// ломает часть потоков и даёт симптомы вроде "нет интернета" в YouTube UI.
	//
	// Для TCP мы теперь полагаемся на:
	//   - HostnameRules после анализа ClientHello/SNI
	//   - direct-by-default, если hostname ещё не известен
	if normalizedHostname == "" && m.isGoogleIP(ip) {
		// Если discovery уже выбрал лучшую стратегию — используем её
		// только для QUIC/UDP case.
		if protocol == "udp" {
			if s := m.activeStrategyForKnownService(protocol, port); s != nil {
				log.Printf("[SELECT] Active strategy for Google QUIC IP %s:%d → strategy %d (%s)",
					ip, port, s.ID, s.Name)
				return s
			}

			if s := m.selectByHintOrder([]string{"quic-fake", "yt-multidisorder", "yt-syndata", "youtube"}, protocol, port); s != nil {
				log.Printf("[SELECT] Google QUIC IP %s:%d → strategy %d (%s)", ip, port, s.ID, s.Name)
				return s
			}
		}
	}

	// 5. Telegram observed-IP fallback
	// Часть Telegram Web backend-потоков в текущих прогонах приходит без hostname
	// и успевает уйти в passthrough до того, как SNI/кэш доедут до селектора.
	if normalizedHostname == "" && protocol == "tcp" && port == 443 && isTelegramObservedFallbackIP(ip) {
		if s, ok := m.GetStrategy(12); ok && s != nil {
			log.Printf("[SELECT] Telegram observed IP %s:%d → strategy %d (%s)", ip, port, s.ID, s.Name)
			return s
		}
	}

	// 6. Direct-by-default
	if ps := m.passthroughStrategy(); ps != nil {
		if normalizedHostname != "" {
			log.Printf("[SELECT] Direct-by-default hostname=%q ip=%s:%d → passthrough", normalizedHostname, ip, port)
		} else {
			log.Printf("[SELECT] Direct-by-default ip=%s:%d → passthrough", ip, port)
		}
		return ps
	}

	log.Printf("[SELECT] No passthrough strategy configured for %s:%d (hostname=%q)", ip, port, normalizedHostname)
	return nil
}

// Вспомогательные функции
func (m *Manager) isDiscoveryRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.discoveryRunning
}

func labelFrom(ip, hostname string) string {
	if hostname != "" {
		return "hostname='" + strings.ToLower(hostname) + "'"
	}
	return "IP='" + ip + "'"
}

// inferHostnameForIP возвращает каноническое hostname для IP по builtinHostnameMappings.
// Используется для QUIC-пакетов где SNI отсутствует: Google IP → "youtube.com".
// Не выполняет reverse DNS — только проверяет Google-диапазоны.
func (m *Manager) inferHostnameForIP(ip string) string {
	if m.isGoogleIP(ip) {
		// Approximate inference для поддержки HostnameRules на QUIC.
		// Все Google-диапазоны считаются youtube.com.
		// GCP VMs / другие сервисы Google могут попасть под youtube-стратегию —
		// это приемлемая цена для основного сценария (YouTube bypass).
		return "youtube.com"
	}
	return ""
}

var telegramObservedFallbackIPs = map[string]struct{}{
	// Наблюдаемые backend IP Telegram Web из последних логов/pcap.
	"149.154.167.99": {},
	"79.133.168.12":  {},
	"108.181.1.241":  {},
	"193.41.141.68":  {},
}

func isTelegramObservedFallbackIP(ip string) bool {
	_, ok := telegramObservedFallbackIPs[ip]
	return ok
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

// ValidateRuntimeAssets проверяет, что стратегии, которым нужны runtime-asset'ы,
// действительно имеют загруженные данные, а не только имена файлов в конфиге.
//
// Это fail-fast защита: лучше упасть на старте с понятной ошибкой,
// чем silently сломать TLS/QUIC в рантайме.
func (m *Manager) ValidateRuntimeAssets() error {
	strategies := m.ListStrategies()

	for _, s := range strategies {
		if s == nil {
			continue
		}

		if s.NeedsSeqOvl() {
			if strings.TrimSpace(s.SeqOvlPatternFile) == "" {
				return fmt.Errorf("strategy %d (%s): split_mode=seqovl but seqovl_pattern_file is empty", s.ID, s.Name)
			}
			if len(s.SeqOvlPatternData) == 0 {
				return fmt.Errorf(
					"strategy %d (%s): seqovl_pattern_file=%q configured but SeqOvlPatternData is empty (asset not loaded)",
					s.ID, s.Name, s.SeqOvlPatternFile,
				)
			}
		}

		if len(s.FakeTLSFiles) > 0 {
			if len(s.FakeTLSFilesData) != len(s.FakeTLSFiles) {
				return fmt.Errorf(
					"strategy %d (%s): fake_tls_files configured=%d but loaded fake TLS assets=%d",
					s.ID, s.Name, len(s.FakeTLSFiles), len(s.FakeTLSFilesData),
				)
			}

			for i, data := range s.FakeTLSFilesData {
				if len(data) == 0 {
					return fmt.Errorf(
						"strategy %d (%s): fake_tls_files[%d]=%q loaded as empty data",
						s.ID, s.Name, i, s.FakeTLSFiles[i],
					)
				}
			}
		}

		if strings.TrimSpace(s.FakeHTTPFile) != "" && len(s.FakeHTTPFileData) == 0 {
			return fmt.Errorf(
				"strategy %d (%s): fake_http_file=%q configured but FakeHTTPFileData is empty",
				s.ID, s.Name, s.FakeHTTPFile,
			)
		}

		if strings.TrimSpace(s.FakeQUICFile) != "" && len(s.FakeQUICFileData) == 0 {
			return fmt.Errorf(
				"strategy %d (%s): fake_quic_file=%q configured but FakeQUICFileData is empty",
				s.ID, s.Name, s.FakeQUICFile,
			)
		}

		if strings.TrimSpace(s.FakeUnknownUDPFile) != "" && len(s.FakeUnknownUDPFileData) == 0 {
			return fmt.Errorf(
				"strategy %d (%s): fake_unknown_udp_file=%q configured but FakeUnknownUDPFileData is empty",
				s.ID, s.Name, s.FakeUnknownUDPFile,
			)
		}
	}

	return nil
}

func readStrategyAsset(baseDir, name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("empty asset name")
	}

	assetPath := name
	if !filepath.IsAbs(assetPath) {
		assetPath = filepath.Join(baseDir, name)
	}
	assetPath = filepath.Clean(assetPath)

	data, err := os.ReadFile(assetPath)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", assetPath, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("asset %q is empty", assetPath)
	}

	return data, nil
}

func (m *Manager) loadAssetsIntoStrategy(s *Strategy, baseDir string) error {
	if s == nil {
		return nil
	}

	// SeqOvl pattern
	if strings.TrimSpace(s.SeqOvlPatternFile) != "" {
		data, err := readStrategyAsset(baseDir, s.SeqOvlPatternFile)
		if err != nil {
			return fmt.Errorf("seqovl_pattern_file=%q: %w", s.SeqOvlPatternFile, err)
		}
		s.SeqOvlPatternData = append(s.SeqOvlPatternData[:0], data...)
	}

	// Fake TLS files
	if len(s.FakeTLSFiles) > 0 {
		s.FakeTLSFilesData = make([][]byte, 0, len(s.FakeTLSFiles))
		for _, name := range s.FakeTLSFiles {
			data, err := readStrategyAsset(baseDir, name)
			if err != nil {
				return fmt.Errorf("fake_tls_file=%q: %w", name, err)
			}
			s.FakeTLSFilesData = append(s.FakeTLSFilesData, append([]byte(nil), data...))
		}
	}

	// Fake HTTP
	if strings.TrimSpace(s.FakeHTTPFile) != "" {
		data, err := readStrategyAsset(baseDir, s.FakeHTTPFile)
		if err != nil {
			return fmt.Errorf("fake_http_file=%q: %w", s.FakeHTTPFile, err)
		}
		s.FakeHTTPFileData = append(s.FakeHTTPFileData[:0], data...)
	}

	// Fake QUIC
	if strings.TrimSpace(s.FakeQUICFile) != "" {
		data, err := readStrategyAsset(baseDir, s.FakeQUICFile)
		if err != nil {
			return fmt.Errorf("fake_quic_file=%q: %w", s.FakeQUICFile, err)
		}
		s.FakeQUICFileData = append(s.FakeQUICFileData[:0], data...)
	}

	// Fake unknown UDP
	if strings.TrimSpace(s.FakeUnknownUDPFile) != "" {
		data, err := readStrategyAsset(baseDir, s.FakeUnknownUDPFile)
		if err != nil {
			return fmt.Errorf("fake_unknown_udp_file=%q: %w", s.FakeUnknownUDPFile, err)
		}
		s.FakeUnknownUDPFileData = append(s.FakeUnknownUDPFileData[:0], data...)
	}

	return nil
}

// LoadRuntimeAssets загружает все file-backed runtime asset'ы для уже активных стратегий.
// Вызывать на старте ПОСЛЕ loadDefaultStrategies()/LoadFromFile() и ДО ValidateRuntimeAssets().
func (m *Manager) LoadRuntimeAssets(baseDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		baseDir = "."
	}

	for _, s := range m.strategies {
		if s == nil {
			continue
		}
		if err := m.loadAssetsIntoStrategy(s, baseDir); err != nil {
			return fmt.Errorf("strategy %d (%s): %w", s.ID, s.Name, err)
		}
	}

	return nil
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
	if m.activeID > 0 {
		if _, ok := m.strategies[m.activeID]; ok {
			stats.ActiveStrategies = 1
		} else {
			stats.ActiveStrategies = 0
		}
	} else {
		stats.ActiveStrategies = 0
	}
	return stats
}

// loadDefaultStrategies is implemented as a method in profiles.go
