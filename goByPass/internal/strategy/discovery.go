package strategy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
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
	CompletedTests int64
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

// runDiscovery основной цикл подбора.
//
// Тесты одного домена сериализованы — горутины для одного домена не запускаются
// параллельно, так как SetTestOverride перезаписывает глобальное состояние.
// Разные домены тестируются параллельно (в пределах MaxConcurrent).
func (d *Discovery) runDiscovery() {
	strategies := d.manager.ListStrategies()
	domains := d.config.TestDomains
	ports := d.config.TestPorts

	d.progress.TotalTests = len(strategies) * len(domains) * len(ports)

	// Семафор для ограничения общей конкурентности
	semaphore := make(chan struct{}, d.config.MaxConcurrent)
	var wg sync.WaitGroup

	// Итерируем по доменам во внешнем цикле — все стратегии для одного домена
	// тестируются последовательно внутри одной горутины.
	// Это гарантирует что SetTestOverride(domain, ...) не перезаписывается
	// параллельной горутиной для того же домена.
	for _, domain := range domains {
		for _, port := range ports {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(domain string, port int) {
				defer wg.Done()
				defer func() { <-semaphore }()

				for _, strat := range strategies {
					select {
					case <-d.stopChan:
						return
					default:
					}
					d.testStrategy(strat, domain, port)
				}
			}(domain, port)
		}
	}

	wg.Wait()
	d.running = false
}

// testStrategy тестирует стратегию на одном домене.
//
// Как это работает:
//  1. SetTestOverride(domain, strategy.ID) — WinDivert pipeline начнёт применять
//     эту стратегию ко всем пакетам с SNI == domain
//  2. Для QUIC-стратегий дополнительно SetTestOverrideByIP() — SNI недоступен
//     в QUIC-пакетах, поэтому override по hostname не сработает (#5).
//  3. testConnection() — реальное TLS-соединение через ОС; пакеты перехватываются
//     WinDivert и модифицируются согласно выбранной стратегии
//  4. ClearTestOverride / ClearTestOverrideByIP — снимаем форсирование
func (d *Discovery) testStrategy(strategy *Strategy, domain string, port int) {
	result := &DiscoveryResult{
		StrategyID: strategy.ID,
		Timestamp:  time.Now(),
	}

	// Форсируем стратегию для этого домена на время теста.
	// ClearTestOverride вызывается в defer — гарантированное снятие даже при панике.
	d.manager.SetTestOverride(domain, strategy.ID)
	defer d.manager.ClearTestOverride(domain)

	// Для QUIC-стратегий: резолвим IP домена и регистрируем override по IP (#5).
	// QUIC-пакеты зашифрованы — SNI из них не извлечь, hostname в flow будет пустым.
	// SelectStrategy для UDP проверяет testOverrides["ip:<addr>"] как fallback.
	var resolvedIPs []string
	if strategy.ApplyToQUIC || strategy.FakeQUICFile != "" {
		if addrs, err := net.LookupHost(domain); err == nil {
			for _, addr := range addrs {
				d.manager.SetTestOverrideByIP(addr, strategy.ID)
				resolvedIPs = append(resolvedIPs, addr)
			}
		} else {
			log.Printf("[DISCOVERY] Warning: failed to resolve %s for QUIC override: %v", domain, err)
		}
		defer func() {
			for _, addr := range resolvedIPs {
				d.manager.ClearTestOverrideByIP(addr)
			}
		}()
	}

	log.Printf("[DISCOVERY] Testing strategy %d (%s) on %s:%d (QUIC IPs: %v)",
		strategy.ID, strategy.Name, domain, port, resolvedIPs)

	for i := 0; i < d.config.SamplesPerTest; i++ {
		time.Sleep(d.config.TestInterval)

		select {
		case <-d.stopChan:
			return
		default:
		}

		start := time.Now()
		err := d.testConnection(domain, port)
		duration := time.Since(start)

		result.Samples++
		if err == nil {
			result.SuccessSamples++
			result.AvgResponse += duration
		} else {
			result.FailSamples++
			if len(result.Errors) < 10 {
				result.Errors = append(result.Errors, err.Error())
			}
		}
	}

	if result.SuccessSamples > 0 {
		result.AvgResponse = result.AvgResponse / time.Duration(result.SuccessSamples)
	}
	result.SuccessRate = float64(result.SuccessSamples) / float64(result.Samples)

	log.Printf("[DISCOVERY] Strategy %d (%s) on %s: %.0f%% success (%d/%d), avg=%v",
		strategy.ID, strategy.Name, domain,
		result.SuccessRate*100, result.SuccessSamples, result.Samples, result.AvgResponse)

	d.mu.Lock()
	d.results[strategy.ID] = result
	d.mu.Unlock()

	atomic.AddInt64(&d.progress.CompletedTests, 1)
}

// testConnection тестирует соединение с доменом
func (d *Discovery) testConnection(domain string, port int) error {
	addr := fmt.Sprintf("%s:%d", domain, port)
	dialer := &net.Dialer{Timeout: d.config.TestTimeout}

	if port == 443 {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

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
