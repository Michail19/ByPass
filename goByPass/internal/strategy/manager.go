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

// Manager управляет стратегиями
type Manager struct {
	strategies   map[int]*Strategy
	defaultID    int
	activeID     int
	filters      map[string]*StrategyFilter
	stats        ManagerStats
	mu           sync.RWMutex
	updateChan   chan *StrategyResult
	closeChan    chan struct{}
	googleRanges []*net.IPNet
	// cidrIndex — индекс по первому октету для быстрого отсева.
	// Большинство проверок отклоняется на первом октете без перебора всего списка.
	cidrIndex      map[byte][]*net.IPNet
	rangesMu       sync.RWMutex
	lastUpdateTime time.Time
	updateErr      error
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
		strategies:   make(map[int]*Strategy),
		filters:      make(map[string]*StrategyFilter),
		updateChan:   make(chan *StrategyResult, 1000),
		closeChan:    make(chan struct{}),
		googleRanges: make([]*net.IPNet, 0),
		cidrIndex:    make(map[byte][]*net.IPNet),
	}

	// Загружаем стратегии по умолчанию
	m.loadDefaultStrategies()

	// Запускаем обработчик результатов
	go m.processResults()

	// Запускаем авто-обновление Google IP ranges
	go m.startGoogleIPUpdater()

	// Первичная загрузка при старте
	m.updateGoogleIPRanges()

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

// fallbackRanges ...
var fallbackRanges = []string{
	// Минимальный набор для YouTube (актуально на 2026)
	"8.8.4.0/24",
	"8.8.8.0/24",
	"8.34.208.0/20",
	"8.35.192.0/20",
	"8.228.0.0/14",
	"8.232.0.0/14",
	"8.236.0.0/15",
	"23.236.48.0/20",
	"23.251.128.0/19",
	"34.0.0.0/15",
	"34.2.0.0/16",
	"34.3.0.0/23",
	"34.3.3.0/24",
	"34.3.4.0/24",
	"34.3.8.0/21",
	"34.3.16.0/20",
	"34.3.32.0/19",
	"34.3.64.0/18",
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
	"35.252.0.0/14",
	"64.15.112.0/20",
	"64.233.112.0/20",
	"70.32.112.0/20",
	"74.114.24.0/21",
	"104.154.0.0/15",
	"104.196.0.0/14",
	"104.237.160.0/19",
	"107.167.160.0/19",
	"107.178.192.0/18",
	"108.59.80.0/20",
	"108.170.192.0/18",
	"74.125.0.0/16",
	"142.250.0.0/15",
	"172.217.0.0/16",
	"172.253.0.0/16",
	"173.194.0.0/16",
	"209.85.128.0/17",
	"216.58.192.0/19",
	"216.239.32.0/19",
	"64.233.160.0/19",
	"66.102.0.0/20",
	"66.249.64.0/19",
	"72.14.192.0/18",
	"108.177.0.0/17",
	"130.211.0.0/16",
	"136.22.2.0/23",
	"136.22.4.0/23",
	"136.22.8.0/22",
	"136.22.160.0/20",
	"136.22.176.0/21",
	"136.22.184.0/23",
	"136.22.186.0/24",
	"136.23.48.0/20",
	"136.23.64.0/18",
	"136.64.0.0/11",
	"136.107.0.0/16",
	"136.108.0.0/14",
	"136.112.0.0/13",
	"136.120.0.0/22",
	"136.124.0.0/15",
	"142.250.0.0/15",
	"146.148.0.0/17",
	"162.120.128.0/17",
	"162.216.148.0/22",
	"162.222.176.0/21",
	"172.110.32.0/21",
	"172.217.0.0/16",
	"172.253.0.0/16",
	"173.194.0.0/16",
	"173.255.112.0/20",
	"192.104.160.0/23",
	"192.158.28.0/22",
	"192.178.0.0/15",
	"193.186.4.0/24",
	"199.36.154.0/23",
	"199.36.156.0/24",
	"199.192.112.0/22",
	"199.223.232.0/21",
	"207.175.0.0/16",
	"207.223.160.0/20",
	"208.65.152.0/22",
	"208.68.108.0/22",
	"208.81.188.0/22",
	"208.117.224.0/19",
	"209.85.128.0/17",
	"216.58.192.0/19",
	"216.73.80.0/20",
	"216.239.32.0/19",
	"216.252.220.0/22",
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
		// Индексируем по первому октету (IPv4 хранится в последних 4 байтах IP в Go)
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

	log.Printf("[GoogleIP] Loaded %d IPv4 ranges (fallback=%t)", len(newRanges), len(allPrefixes) == len(fallbackRanges))
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
		log.Printf("[GoogleIP] No ranges loaded, using hostname fallback")
		return false
	}

	// Быстрая проверка по первому октету
	candidates, ok := m.cidrIndex[ip4[0]]
	if !ok {
		return false // нет ни одной сети с таким первым октетом
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

// AddStrategy добавляет стратегию
func (m *Manager) AddStrategy(strategy *Strategy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strategy.ID == 0 {
		// Генерируем ID
		strategy.ID = len(m.strategies) + 1
	}

	if _, exists := m.strategies[strategy.ID]; exists {
		return fmt.Errorf("strategy with ID %d already exists", strategy.ID)
	}

	m.strategies[strategy.ID] = strategy
	m.stats.TotalStrategies++

	return nil
}

// GetStrategy возвращает стратегию по ID
func (m *Manager) GetStrategy(id int) (*Strategy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	strat, exists := m.strategies[id]
	return strat, exists
}

// hostnameStrategyID возвращает ID стратегии по подстроке hostname.
// Проверки идут в порядке убывания специфичности.
// Возвращает 0 если совпадений нет.
var hostnameRules = []struct {
	contains   string
	strategyID int
}{
	// Google / YouTube / CDN — стратегия 25 (zapret general.bat)
	{"youtube.com", 25},
	{"googlevideo.com", 25}, // стриминг YouTube
	{"googleapis.com", 25},
	{"gstatic.com", 25},
	{"ggpht.com", 25},
	{"ytimg.com", 25},
	{"youtu.be", 25},
	{"googleusercontent.com", 25},
	{"google.com", 25},
	{"gmail.com", 25},
	// Discord
	{"discord.com", 21},
	{"discord.gg", 21},
	{"discordapp.com", 21},
	{"discordapp.net", 21},
	{"discord.media", 21},
	// Telegram
	{"telegram.org", 12},
	{"telegram.me", 12},
	{"t.me", 12},
}

// SelectStrategy выбирает стратегию для пакета.
//
// Порядок приоритетов:
//  1. IP входит в диапазоны Google → strategy 25
//  2. Hostname содержит известный домен → соответствующая стратегия
//  3. Fallback: стратегия с наименьшим Priority (меньше = важнее),
//     при этом стратегия 1 (passthrough) никогда не выбирается в fallback —
//     только явно через pipeline как последний резерв.
func (m *Manager) SelectStrategy(ip, hostname string, port int, protocol string) *Strategy {
	log.Printf("[SELECT] Called for IP %s:%d, hostname='%s'", ip, port, hostname)

	// 1. Проверка по IP — самый надёжный способ для YouTube/CDN
	//    (hostname может отсутствовать при первых пакетах потока)
	if m.isGoogleIP(ip) {
		m.mu.RLock()
		strat, exists := m.strategies[25]
		m.mu.RUnlock()
		if exists {
			log.Printf("[SELECT] Google/YouTube IP match: %s → strategy 25 (%s)", ip, strat.Name)
			return strat
		}
		// strategy 25 не загружена — ищем strategy 20 как запасную
		m.mu.RLock()
		strat, exists = m.strategies[20]
		m.mu.RUnlock()
		if exists {
			log.Printf("[SELECT] Google IP fallback: %s → strategy 20 (%s)", ip, strat.Name)
			return strat
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	lower := strings.ToLower(hostname)
	log.Printf("[SELECT] Hostname lookup: '%s'", lower)

	// 2. Hostname-матч
	if lower != "" {
		for _, rule := range hostnameRules {
			if strings.Contains(lower, rule.contains) {
				if strat, exists := m.strategies[rule.strategyID]; exists {
					log.Printf("[SELECT] Hostname match '%s' ⊃ '%s' → strategy %d (%s)",
						lower, rule.contains, strat.ID, strat.Name)
					return strat
				}
			}
		}
	}

	// 3. Fallback: лучшая не-passthrough стратегия для данного протокола/порта.
	//    isPassthrough() проверяет, что у стратегии нет реальных модификаций.
	var best *Strategy
	bestPriority := int(^uint(0) >> 1) // MaxInt

	for _, strat := range m.strategies {
		if strat.ID == 1 || isPassthrough(strat) {
			continue // никогда не выбираем passthrough в fallback
		}
		// TCP: WinDivert уже ограничивает 80/443 — порт не проверяем
		// UDP: строго port==443 — иначе udp:53 (DNS) попадёт под QUIC-стратегию
		protocolMatch := (protocol == "tcp" && (strat.ApplyToTLS || strat.ApplyToHTTP)) ||
			(protocol == "udp" && port == 443 && strat.ApplyToQUIC)
		if !protocolMatch {
			continue
		}
		if strat.Priority < bestPriority {
			best = strat
			bestPriority = strat.Priority
		}
	}

	if best != nil {
		log.Printf("[SELECT] Fallback → strategy %d (%s) priority=%d", best.ID, best.Name, best.Priority)
		return best
	}

	log.Printf("[SELECT] No non-passthrough strategy found for %s:%d (hostname: '%s')", ip, port, hostname)
	return nil
}

// isPassthrough возвращает true если стратегия не делает никаких реальных модификаций.
// Такие стратегии не должны выигрывать fallback-выбор.
func isPassthrough(s *Strategy) bool {
	return s.SplitMode == SplitNone &&
		s.DisorderMode == DisorderNone &&
		s.Fooling == 0 &&
		!s.SynData &&
		!s.MultiDisorder &&
		!s.FakedSplit &&
		s.SeqOvlLen == 0
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

// UpdateStrategy обновляет статистику стратегии
func (m *Manager) UpdateStrategy(id int, success bool, responseTime time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	strat, exists := m.strategies[id]
	if !exists {
		return
	}

	strat.LastUsed = time.Now()

	if success {
		strat.SuccessCount++
		m.stats.SuccessfulAttempts++

		// Обновляем среднее время ответа
		if strat.AvgResponseMs == 0 {
			strat.AvgResponseMs = responseTime.Milliseconds()
		} else {
			strat.AvgResponseMs = (strat.AvgResponseMs*int64(strat.SuccessCount-1) +
				responseTime.Milliseconds()) / int64(strat.SuccessCount)
		}
	} else {
		strat.FailCount++
		m.stats.FailedAttempts++
	}
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
			// Drain channel to avoid leaks
			for len(m.updateChan) > 0 {
				<-m.updateChan
			}
			return
		case result := <-m.updateChan:
			m.UpdateStrategy(result.StrategyID, result.Success, result.ResponseTime)
		}
	}
}

// ListStrategies возвращает список всех стратегий
func (m *Manager) ListStrategies() []*Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	strategies := make([]*Strategy, 0, len(m.strategies))
	for _, strat := range m.strategies {
		strategies = append(strategies, strat)
	}

	// Сортируем по приоритету
	sort.Slice(strategies, func(i, j int) bool {
		return strategies[i].Priority < strategies[j].Priority
	})

	return strategies
}

// SaveToFile сохраняет стратегии в файл
func (m *Manager) SaveToFile(filename string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.strategies, "", " ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadFromFile загружает стратегии из файла
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

		// Очищаем существующие стратегии
		m.strategies = make(map[int]*Strategy)

		// Добавляем каждую стратегию из массива
		for _, s := range strategiesArray {
			if s.ID == 0 {
				continue
			}
			m.strategies[s.ID] = s
		}
		m.stats.TotalStrategies = len(m.strategies)
		return nil
	}

	// Если не получилось как массив, пробуем как map (старый формат)
	var strategiesMap map[int]*Strategy
	if err := json.Unmarshal(data, &strategiesMap); err != nil {
		return fmt.Errorf("failed to parse strategies: %v (tried array and map)", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.strategies = strategiesMap
	m.stats.TotalStrategies = len(strategiesMap)
	return nil
}

// GetStats возвращает статистику
func (m *Manager) GetStats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	stats.TotalStrategies = len(m.strategies)
	stats.ActiveStrategies = 1
	if m.activeID > 0 {
		stats.ActiveStrategies = 1
	}

	return stats
}

// loadDefaultStrategies is implemented as a method in profiles.go
