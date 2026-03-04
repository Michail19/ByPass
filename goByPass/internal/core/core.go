package core

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"ByPass/internal/cache"
	"ByPass/internal/capture"
	"ByPass/internal/config"
	"ByPass/internal/conntrack"
	"ByPass/internal/firewall"
	"ByPass/internal/modifier"
	"ByPass/internal/packetflow"
	"ByPass/internal/protocol"
	"ByPass/internal/sender"
	"ByPass/internal/strategy"
	"ByPass/pkg/models"
)

// Core представляет ядро приложения
type Core struct {
	// Конфигурация
	config *config.Config

	// Компоненты
	ipCache     *cache.IPCache
	domainCache *cache.DomainCache
	conntrack   *conntrack.Manager
	analyzer    *protocol.Analyzer
	strategyMgr *strategy.Manager
	modifier    *modifier.PacketModifier
	sender      sender.Sender
	capturer    capture.Capturer
	pipeline    *packetflow.Pipeline
	firewall    firewall.Manager

	// Управление
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	running   bool
	startTime time.Time

	// Статистика
	stats CoreStats
}

// CoreStats общая статистика ядра
type CoreStats struct {
	StartTime        time.Time
	UptimeSeconds    int64
	PacketsReceived  uint64
	PacketsProcessed uint64
	PacketsModified  uint64
	PacketsSent      uint64
	PacketsDropped   uint64
	FlowsTracked     int
	CacheHits        uint64
	CacheMisses      uint64
	Errors           uint64
}

// NewCore создает новое ядро приложения
func NewCore(cfg *config.Config) *Core {
	return &Core{
		config:    cfg,
		startTime: time.Now(),
		stats:     CoreStats{StartTime: time.Now()},
	}
}

// Init инициализирует все компоненты
func (c *Core) Init() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Println("Initializing core components...")

	// Кэши
	c.ipCache = cache.NewIPCache(
		c.config.Cache.IPCache.TTL,
		c.config.Cache.IPCache.MaxSize,
	)

	c.domainCache = cache.NewDomainCache(
		c.config.Cache.DomainCache.TTL,
		c.config.Cache.DomainCache.MaxSize,
	)

	// Предзагружаем популярные домены
	if len(c.config.Cache.DomainCache.Preload) > 0 {
		go c.domainCache.Preload(c.config.Cache.DomainCache.Preload)
	}

	// Менеджер потоков
	c.conntrack = conntrack.NewManager(
		c.config.Conntrack.Timeout,
		c.config.Conntrack.MaxFlows,
	)

	// Анализатор протоколов
	c.analyzer = protocol.NewAnalyzer()

	// Менеджер стратегий
	c.strategyMgr = strategy.NewManager()
	if c.config.Strategy.StrategyFile != "" {
		if err := c.strategyMgr.LoadFromFile(c.config.Strategy.StrategyFile); err != nil {
			log.Printf("Warning: failed to load strategies: %v", err)
		}
	}

	// Устанавливаем стратегию по умолчанию
	for _, s := range c.strategyMgr.ListStrategies() {
		if s.Name == c.config.Strategy.DefaultStrategy {
			c.strategyMgr.SetDefault(s.ID)
			break
		}
	}

	// Модификатор пакетов
	c.modifier = modifier.NewPacketModifier(c.strategyMgr, c.ipCache)

	// Отправитель
	sender, err := sender.NewSender(sender.Config{
		Interface:   c.config.Sender.Interface,
		BufferSize:  c.config.Sender.BufferSize,
		SendTimeout: c.config.Sender.SendTimeout,
		BatchSize:   c.config.Sender.BatchSize,
	})
	if err != nil {
		return fmt.Errorf("failed to create sender: %v", err)
	}
	c.sender = sender

	// Захватчик
	capturer, err := capture.NewNFQueue(capture.Config{
		QueueNum:     c.config.Capture.QueueNum,
		BufferSize:   c.config.Capture.BufferSize,
		Interface:    c.config.Capture.Interface,
		MaxPacketLen: c.config.Capture.MaxPacketLen,
	})
	if err != nil {
		c.sender.Close()
		return fmt.Errorf("failed to create capturer: %v", err)
	}
	c.capturer = capturer

	// Конвейер
	c.pipeline = packetflow.NewPipeline(
		c.capturer,
		c.conntrack,
		c.modifier,
		c.sender,
		c.analyzer,
		c.ipCache,
		c.domainCache,
		c.strategyMgr,
		packetflow.Config{
			Workers:         c.config.Pipeline.Workers,
			PacketQueueSize: c.config.Pipeline.PacketQueueSize,
			ResultQueueSize: c.config.Pipeline.ResultQueueSize,
			ProcessTimeout:  c.config.Pipeline.ProcessTimeout,
		},
	)

	// Файрвол
	fw, err := firewall.NewManager(firewall.Config{
		Backend:       c.config.Firewall.Backend,
		QueueNum:      c.config.Capture.QueueNum,
		Ports:         c.config.Firewall.Ports,
		Direction:     c.config.Firewall.Direction,
		ExcludeIPs:    c.config.Firewall.ExcludeIPs,
		ExcludePorts:  c.config.Firewall.ExcludePorts,
		CleanupOnExit: c.config.Firewall.CleanupOnExit,
	})
	if err != nil {
		c.cleanup()
		return fmt.Errorf("failed to create firewall manager: %v", err)
	}
	c.firewall = fw

	log.Println("Core initialized successfully")
	return nil
}

// Start запускает ядро
func (c *Core) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("core already running")
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.running = true
	c.startTime = time.Now()

	log.Println("Starting core...")

	// Настраиваем файрвол
	if err := c.firewall.AddRule(
		c.config.Capture.QueueNum,
		c.config.Firewall.Ports,
		c.config.Firewall.Direction,
	); err != nil {
		return fmt.Errorf("failed to setup firewall: %v", err)
	}

	// Запускаем конвейер
	if err := c.pipeline.Start(); err != nil {
		c.firewall.RemoveRule(
			c.config.Capture.QueueNum,
			c.config.Firewall.Ports,
			c.config.Firewall.Direction,
		)
		return fmt.Errorf("failed to start pipeline: %v", err)
	}

	// Запускаем мониторинг статистики
	c.wg.Add(1)
	go c.statsCollector()

	// Запускаем авто-дискавери если нужно
	if c.config.Strategy.AutoDiscovery.Enabled {
		c.wg.Add(1)
		go c.runDiscovery()
	}

	log.Println("Core started successfully")
	return nil
}

// Stop останавливает ядро
func (c *Core) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	log.Println("Stopping core...")

	c.cancel()
	c.wg.Wait()

	// Останавливаем конвейер
	c.pipeline.Stop()

	// Очищаем правила файрвола
	if c.config.Firewall.CleanupOnExit {
		c.firewall.RemoveRule(
			c.config.Capture.QueueNum,
			c.config.Firewall.Ports,
			c.config.Firewall.Direction,
		)
	}

	c.running = false
	c.cleanup()

	log.Println("Core stopped")
	return nil
}

// cleanup освобождает ресурсы
func (c *Core) cleanup() {
	if c.sender != nil {
		c.sender.Close()
	}
	if c.capturer != nil {
		c.capturer.Stop()
	}
	if c.conntrack != nil {
		c.conntrack.Stop()
	}
	if c.strategyMgr != nil {
		c.strategyMgr.Stop()
	}
}

// statsCollector собирает статистику
func (c *Core) statsCollector() {
	defer c.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.updateStats()
		}
	}
}

// updateStats обновляет статистику
func (c *Core) updateStats() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pipeline == nil {
		return
	}

	pipelineStats := c.pipeline.GetStats()
	connStats := c.conntrack.GetStats()

	c.stats.UptimeSeconds = int64(time.Since(c.startTime).Seconds())
	c.stats.PacketsReceived = pipelineStats.PacketsReceived
	c.stats.PacketsProcessed = pipelineStats.PacketsProcessed
	c.stats.PacketsModified = pipelineStats.PacketsModified
	c.stats.PacketsSent = pipelineStats.PacketsSent
	c.stats.PacketsDropped = pipelineStats.PacketsDropped
	c.stats.FlowsTracked = connStats.ActiveFlows
	c.stats.CacheHits = pipelineStats.CacheHits
	c.stats.CacheMisses = pipelineStats.CacheMisses
}

// GetStats возвращает статистику
func (c *Core) GetStats() CoreStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// GetFlows возвращает список активных потоков
func (c *Core) GetFlows() []*models.Flow {
	if c.conntrack == nil {
		return nil
	}

	flows := c.conntrack.GetFlows()
	result := make([]*models.Flow, len(flows))
	for i, f := range flows {
		info := f.GetInfo()
		result[i] = &models.Flow{
			Key: models.FlowKey{
				SrcIP: info["key"].(string),
			},
			State:      models.FlowState(info["state"].(string)),
			CreatedAt:  info["created"].(time.Time),
			UpdatedAt:  info["updated"].(time.Time),
			PacketsIn:  info["packets_in"].(uint64),
			PacketsOut: info["packets_out"].(uint64),
			BytesIn:    info["bytes_in"].(uint64),
			BytesOut:   info["bytes_out"].(uint64),
			Hostname:   info["hostname"].(string),
			IsTLS:      info["is_tls"].(bool),
			IsHTTP:     info["is_http"].(bool),
		}
	}
	return result
}

// GetStrategies возвращает список стратегий
func (c *Core) GetStrategies() []*models.Strategy {
	if c.strategyMgr == nil {
		return nil
	}

	strategies := c.strategyMgr.ListStrategies()
	result := make([]*models.Strategy, len(strategies))
	for i, s := range strategies {
		result[i] = &models.Strategy{
			ID:             s.ID,
			Name:           s.Name,
			Description:    s.Description,
			ApplyToHTTP:    s.ApplyToHTTP,
			ApplyToTLS:     s.ApplyToTLS,
			SplitMode:      s.SplitMode.String(),
			SplitPositions: s.SplitPositions,
			DisorderMode:   s.DisorderMode.String(),
			DisorderTTL:    s.DisorderTTL,
			FakeMode:       s.FakeMode.String(),
			FakeTTL:        s.FakeTTL,
			HTTPModMode:    s.HTTPModMode.String(),
			TLSRecordSplit: s.TLSRecordSplit,
			SuccessCount:   s.SuccessCount,
			FailCount:      s.FailCount,
			LastUsed:       s.LastUsed,
			Priority:       s.Priority,
		}
	}
	return result
}

// ReloadConfig перезагружает конфигурацию
func (c *Core) ReloadConfig() error {
	// Здесь можно реализовать горячую перезагрузку
	return nil
}

// runDiscovery запускает авто-подбор стратегий
func (c *Core) runDiscovery() {
	defer c.wg.Done()

	discovery := strategy.NewDiscovery(c.strategyMgr, strategy.DiscoveryConfig{
		TestDomains:    c.config.Strategy.AutoDiscovery.TestDomains,
		TestPorts:      c.config.Strategy.AutoDiscovery.TestPorts,
		TestTimeout:    5 * time.Second,
		TestInterval:   time.Duration(c.config.Strategy.AutoDiscovery.TestInterval) * time.Second,
		SamplesPerTest: 5,
		MinSuccessRate: c.config.Strategy.AutoDiscovery.MinSuccessRate,
	})

	log.Println("Starting auto-discovery...")
	if err := discovery.Start(); err != nil {
		log.Printf("Auto-discovery error: %v", err)
		return
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			discovery.Stop()
			return
		case <-ticker.C:
			results := discovery.GetResults()
			if len(results) > 0 {
				best := results[0]
				log.Printf("Auto-discovery: best strategy %d with success rate %.1f%%",
					best.StrategyID, best.SuccessRate*100)

				if best.SuccessRate >= c.config.Strategy.AutoDiscovery.MinSuccessRate {
					c.strategyMgr.SetActive(best.StrategyID)
					discovery.Stop()
					return
				}
			}
		}
	}
}
