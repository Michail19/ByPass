package strategy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager управляет стратегиями
type Manager struct {
	strategies map[int]*Strategy
	defaultID  int
	activeID   int
	filters    map[string]*StrategyFilter
	stats      ManagerStats
	mu         sync.RWMutex
	updateChan chan *StrategyResult
	closeChan  chan struct{}
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
		strategies: make(map[int]*Strategy),
		filters:    make(map[string]*StrategyFilter),
		updateChan: make(chan *StrategyResult, 1000),
		closeChan:  make(chan struct{}),
	}

	// Загружаем стратегии по умолчанию
	m.loadDefaultStrategies()

	// Запускаем обработчик результатов
	go m.processResults()

	return m
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

// SelectStrategy выбирает стратегию для IP/хоста
func (m *Manager) SelectStrategy(ip, hostname string, port int, protocol string) *Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lower := strings.ToLower(hostname)

	log.Printf("Hostname after: %v", lower)

	// Точные и поддоменные совпадения
	if lower != "" {
		hostRules := map[string]int{
			"youtube.com":           20,
			"www.youtube.com":       20,
			"m.youtube.com":         20,
			"youtu.be":              20,
			"googlevideo.com":       20,
			"ytimg.com":             20,
			"ggpht.com":             20,
			"discord.com":           21,
			"discord.gg":            21,
			"telegram.org":          12,
			"kws2.web.telegram.org": 12,
		}

		// Проверяем поддомены через contains
		if strings.Contains(lower, "youtube") || strings.Contains(lower, "googlevideo") ||
			strings.Contains(lower, "ytimg") || strings.Contains(lower, "ggpht") {
			if strat, exists := m.strategies[20]; exists {
				log.Printf("YouTube subdomain match: %s → strategy 20", hostname)
				return strat
			}
		}

		if strings.Contains(lower, "discord") {
			if strat, exists := m.strategies[21]; exists {
				log.Printf("Discord match: %s → strategy 21", hostname)
				return strat
			}
		}

		if strings.Contains(lower, "telegram.org") {
			if strat, exists := m.strategies[12]; exists {
				log.Printf("Telegram subdomain match: %s → strategy 12", hostname)
				return strat
			}
		}

		// Проверяем точное совпадение
		if id, ok := hostRules[lower]; ok {
			if strat, exists := m.strategies[id]; exists {
				log.Printf("Exact hostname match: %s → strategy %d", hostname, id)
				return strat
			}
		}
	}

	// Fallback на приоритет (как в уровне 1)
	var best *Strategy
	bestPriority := 999999

	for _, strat := range m.strategies {
		if (protocol == "tcp" && (strat.ApplyToTLS || strat.ApplyToHTTP)) ||
			(protocol == "udp" && strat.ApplyToQUIC) {
			if strat.Priority < bestPriority {
				best = strat
				bestPriority = strat.Priority
			}
		}
	}

	if best != nil {
		log.Printf("No specific match, fallback to priority %d: strategy %d (%s)",
			best.Priority, best.ID, best.Name)
		return best
	}

	log.Printf("No strategy found for %s:%d (hostname: %s)", ip, port, hostname)
	return nil
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

	data, err := json.MarshalIndent(m.strategies, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// LoadFromFile загружает стратегии из файла
func (m *Manager) LoadFromFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
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

// loadDefaultStrategies загружает стратегии по умолчанию
var loadDefaultStrategies = func(m *Manager) {
	// Будет заполнено из profiles.go
}
