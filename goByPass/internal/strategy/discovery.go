package strategy

import (
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
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
	MaxConcurrent  int           // максимум одновременных тестов (по доменам)
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
	// FIX #9: sync.Once гарантирует что stopChan закрывается ровно один раз.
	// Было: close(stopChan) вызывался напрямую — повторный вызов Stop() паниковал.
	stopOnce sync.Once
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
		config.MinSuccessRate = 0.7
	}
	if config.SamplesPerTest == 0 {
		config.SamplesPerTest = 10
	}

	// Инициализируем рандом для jitter
	rand.Seed(time.Now().UnixNano())

	return &Discovery{
		manager:  manager,
		config:   config,
		results:  make(map[int]*DiscoveryResult),
		stopChan: make(chan struct{}),
	}
}

// Start запускает автоподбор.
// FIX: d.running читается и пишется под d.mu.Lock() — устраняет data race
// с Stop() и горутиной runDiscovery(), которые тоже пишут это поле.
func (d *Discovery) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("discovery already running")
	}
	d.running = true
	d.manager.SetDiscoveryRunning(true)
	d.progress.StartTime = time.Now()
	d.mu.Unlock()

	go d.runDiscovery()

	return nil
}

// Stop останавливает автоподбор.
// FIX #9: безопасен для многократного вызова благодаря sync.Once.
// FIX race: d.running = false под d.mu.Lock() — синхронизировано с Start().
func (d *Discovery) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopChan)
		d.mu.Lock()
		d.running = false
		d.manager.SetDiscoveryRunning(false)
		d.mu.Unlock()
	})
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

	semaphore := make(chan struct{}, d.config.MaxConcurrent)
	var wg sync.WaitGroup

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
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
}

// testStrategy тестирует стратегию на одном домене.
//
// Как это работает:
//  1. SetTestOverride(domain, strategy.ID) — WinDivert pipeline начнёт применять
//     эту стратегию ко всем пакетам с SNI == domain
//  2. Для QUIC-стратегий дополнительно SetTestOverrideByIP()
//  3. testConnection() — реальное TLS-соединение через ОС
//  4. ClearTestOverride / ClearTestOverrideByIP — снимаем форсирование
func (d *Discovery) testStrategy(strat *Strategy, domain string, port int) {
	result := &DiscoveryResult{
		StrategyID: strat.ID,
		Timestamp:  time.Now(),
	}

	d.manager.SetTestOverride(domain, strat.ID)
	defer d.manager.ClearTestOverride(domain)

	var resolvedIPs []string
	if strat.ApplyToQUIC || strat.FakeQUICFile != "" {
		if addrs, err := net.LookupHost(domain); err == nil {
			for _, addr := range addrs {
				d.manager.SetTestOverrideByIP(addr, strat.ID)
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
		strat.ID, strat.Name, domain, port, resolvedIPs)

	// FIX: обновляем CurrentDomain/Port для GetProgress() (#7 в review).
	// Было: поля никогда не записывались → GetProgress() всегда возвращал пустые значения.
	d.mu.Lock()
	d.progress.CurrentDomain = domain
	d.progress.CurrentPort = port
	d.mu.Unlock()

	// ── Warmup sample (не входит в статистику) ─────────────────────────────
	_ = d.testConnection(domain, port) // просто прогреваем DNS/TCP/TLS

	// ── Основные SamplesPerTest с jitter ───────────────────────────────────
	for i := 0; i < d.config.SamplesPerTest; i++ {
		// Jitter 0..50ms чтобы DPI не детектил паттерн
		jitter := time.Duration(rand.Intn(51)) * time.Millisecond
		time.Sleep(d.config.TestInterval + jitter)

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
		strat.ID, strat.Name, domain,
		result.SuccessRate*100, result.SuccessSamples, result.Samples, result.AvgResponse)

	// Сохраняем только лучший результат для этой стратегии
	d.mu.Lock()
	if existing, ok := d.results[strat.ID]; ok {
		if result.SuccessRate > existing.SuccessRate {
			d.results[strat.ID] = result
		}
	} else {
		d.results[strat.ID] = result
	}
	d.mu.Unlock()

	atomic.AddInt64(&d.progress.CompletedTests, 1)
}

// testConnection тестирует соединение с доменом
func (d *Discovery) testConnection(domain string, port int) error {
	addr := fmt.Sprintf("%s:%d", domain, port)
	dialer := &net.Dialer{Timeout: d.config.TestTimeout}

	if port == 443 {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         domain, // правильный SNI
			InsecureSkipVerify: true,   // nolint:gosec // intentional for discovery
		})
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

	request := []byte("GET / HTTP/1.1\r\nHost: " + domain + "\r\nConnection: close\r\n\r\n")

	conn.SetWriteDeadline(time.Now().Add(d.config.TestTimeout))
	if _, err := conn.Write(request); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(d.config.TestTimeout))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return fmt.Errorf("no response")
	}

	return nil
}

// GetResults возвращает результаты подбора, отсортированные по успешности (убыв.)
func (d *Discovery) GetResults() []*DiscoveryResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	results := make([]*DiscoveryResult, 0, len(d.results))
	for _, res := range d.results {
		results = append(results, res)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].SuccessRate > results[j].SuccessRate
	})

	return results
}

// GetBestStrategy возвращает лучший результат с SuccessRate >= MinSuccessRate.
// Возвращает nil если подходящей стратегии ещё нет.
func (d *Discovery) GetBestStrategy() *DiscoveryResult {
	results := d.GetResults()
	for _, res := range results {
		if res.SuccessRate >= d.config.MinSuccessRate {
			return res
		}
	}
	return nil
}

// ApplyBestStrategy применяет лучшую найденную стратегию как активную
func (d *Discovery) ApplyBestStrategy() error {
	best := d.GetBestStrategy()
	if best == nil {
		return fmt.Errorf("no good strategy found (min_success_rate=%.0f%%)", d.config.MinSuccessRate*100)
	}

	return d.manager.SetActive(best.StrategyID)
}

// GetProgress возвращает прогресс подбора
func (d *Discovery) GetProgress() DiscoveryProgress {
	d.mu.RLock()
	defer d.mu.RUnlock()

	progress := d.progress
	completed := atomic.LoadInt64(&d.progress.CompletedTests)
	progress.CompletedTests = completed

	if progress.TotalTests > 0 && completed > 0 {
		elapsed := time.Since(progress.StartTime)
		avgPerTest := elapsed / time.Duration(completed)
		remainingTests := progress.TotalTests - int(completed)
		progress.EstimatedTime = time.Duration(remainingTests) * avgPerTest
	}

	return progress
}
