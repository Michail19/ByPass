package strategy

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// DiscoveryConfig конфигурация для автоподбора
type DiscoveryConfig struct {
	TestDomains    []string      // домены для тестирования
	TestPorts      []int         // порты для тестирования
	TestTimeout    time.Duration // таймаут теста
	TestInterval   time.Duration // интервал между тестами
	MaxConcurrent  int           // максимум одновременных тестов
	MinSuccessRate float64       // минимальный процент успеха
	SamplesPerTest int           // количество проб на тест
}

// DiscoveryResult результат автоподбора
type DiscoveryResult struct {
	StrategyID     int
	SuccessRate    float64
	AvgResponse    time.Duration
	Samples        int
	SuccessSamples int
	FailSamples    int
	Errors         []string
	Timestamp      time.Time
}

// Discovery управляет автоподбором стратегий
type Discovery struct {
	manager  *Manager
	config   DiscoveryConfig
	results  map[int]*DiscoveryResult
	mu       sync.RWMutex
	running  bool
	stopChan chan struct{}
	progress DiscoveryProgress
}

// DiscoveryProgress прогресс автоподбора
type DiscoveryProgress struct {
	TotalTests     int
	CompletedTests int
	CurrentDomain  string
	CurrentPort    int
	StartTime      time.Time
	EstimatedTime  time.Duration
}

// NewDiscovery создает новый автоподборщик
func NewDiscovery(manager *Manager, config DiscoveryConfig) *Discovery {
	if config.TestTimeout == 0 {
		config.TestTimeout = 5 * time.Second
	}
	if config.TestInterval == 0 {
		config.TestInterval = 100 * time.Millisecond
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 5
	}
	if config.MinSuccessRate == 0 {
		config.MinSuccessRate = 0.7 // 70% успеха
	}
	if config.SamplesPerTest == 0 {
		config.SamplesPerTest = 10
	}

	return &Discovery{
		manager:  manager,
		config:   config,
		results:  make(map[int]*DiscoveryResult),
		stopChan: make(chan struct{}),
	}
}

// Start запускает автоподбор
func (d *Discovery) Start() error {
	if d.running {
		return fmt.Errorf("discovery already running")
	}

	d.running = true
	d.progress.StartTime = time.Now()

	// Запускаем в горутине
	go d.runDiscovery()

	return nil
}

// Stop останавливает автоподбор
func (d *Discovery) Stop() {
	if d.running {
		close(d.stopChan)
		d.running = false
	}
}

// runDiscovery основной цикл подбора
func (d *Discovery) runDiscovery() {
	strategies := d.manager.ListStrategies()
	d.progress.TotalTests = len(strategies) * len(d.config.TestDomains) * len(d.config.TestPorts)

	// Используем семафор для ограничения конкурентности
	semaphore := make(chan struct{}, d.config.MaxConcurrent)
	var wg sync.WaitGroup

	for _, strategy := range strategies {
		select {
		case <-d.stopChan:
			return
		default:
		}

		for _, domain := range d.config.TestDomains {
			for _, port := range d.config.TestPorts {
				wg.Add(1)
				semaphore <- struct{}{}

				go func(strat *Strategy, domain string, port int) {
					defer wg.Done()
					defer func() { <-semaphore }()

					d.testStrategy(strat, domain, port)
					d.progress.CompletedTests++
				}(strategy, domain, port)
			}
		}
	}

	wg.Wait()
	d.running = false
}

// testStrategy тестирует стратегию на одном домене
func (d *Discovery) testStrategy(strategy *Strategy, domain string, port int) {
	result := &DiscoveryResult{
		StrategyID: strategy.ID,
		Timestamp:  time.Now(),
	}

	for i := 0; i < d.config.SamplesPerTest; i++ {
		// Небольшая задержка между тестами
		time.Sleep(d.config.TestInterval)

		select {
		case <-d.stopChan:
			return
		default:
		}

		// Пытаемся подключиться к домену
		start := time.Now()
		err := d.testConnection(domain, port)
		duration := time.Since(start)

		result.Samples++
		if err == nil {
			result.SuccessSamples++
			result.AvgResponse += duration
		} else {
			result.FailSamples++
			if len(result.Errors) < 10 { // сохраняем только первые 10 ошибок
				result.Errors = append(result.Errors, err.Error())
			}
		}
	}

	// Вычисляем метрики
	if result.SuccessSamples > 0 {
		result.AvgResponse = result.AvgResponse / time.Duration(result.SuccessSamples)
	}
	result.SuccessRate = float64(result.SuccessSamples) / float64(result.Samples)

	// Сохраняем результат
	d.mu.Lock()
	d.results[strategy.ID] = result
	d.mu.Unlock()
}

// testConnection тестирует соединение с доменом
func (d *Discovery) testConnection(domain string, port int) error {
	addr := fmt.Sprintf("%s:%d", domain, port)

	// Пробуем TCP соединение с таймаутом
	conn, err := net.DialTimeout("tcp", addr, d.config.TestTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Отправляем минимальный запрос
	request := []byte("GET / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n")

	conn.SetWriteDeadline(time.Now().Add(d.config.TestTimeout))
	if _, err := conn.Write(request); err != nil {
		return err
	}

	// Ждем ответ
	conn.SetReadDeadline(time.Now().Add(d.config.TestTimeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return fmt.Errorf("no response")
	}

	return nil
}

// GetResults возвращает результаты подбора
func (d *Discovery) GetResults() []*DiscoveryResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	results := make([]*DiscoveryResult, 0, len(d.results))
	for _, res := range d.results {
		results = append(results, res)
	}

	// Сортируем по успешности
	sort.Slice(results, func(i, j int) bool {
		return results[i].SuccessRate > results[j].SuccessRate
	})

	return results
}

// GetBestStrategy возвращает лучшую стратегию
func (d *Discovery) GetBestStrategy() *DiscoveryResult {
	results := d.GetResults()
	if len(results) == 0 {
		return nil
	}

	// Находим стратегию с максимальной успешностью
	var best *DiscoveryResult
	for _, res := range results {
		if res.SuccessRate >= d.config.MinSuccessRate {
			if best == nil || res.SuccessRate > best.SuccessRate {
				best = res
			}
		}
	}

	return best
}

// ApplyBestStrategy применяет лучшую стратегию
func (d *Discovery) ApplyBestStrategy() error {
	best := d.GetBestStrategy()
	if best == nil {
		return fmt.Errorf("no good strategy found")
	}

	return d.manager.SetActive(best.StrategyID)
}

// GetProgress возвращает прогресс подбора
func (d *Discovery) GetProgress() DiscoveryProgress {
	d.mu.RLock()
	defer d.mu.RUnlock()

	progress := d.progress
	if progress.TotalTests > 0 && progress.CompletedTests > 0 {
		elapsed := time.Since(progress.StartTime)
		progress.EstimatedTime = time.Duration(float64(elapsed) *
			float64(progress.TotalTests) / float64(progress.CompletedTests))
	}

	return progress
}
