package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

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
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
	commit    = "unknown"
)

func main() {
	// Парсим аргументы командной строки
	var (
		configPath  = flag.String("config", "", "path to config file")
		showVersion = flag.Bool("version", false, "show version information")
		queueNum    = flag.Int("queue", -1, "NFQUEUE number (overrides config)")
		ports       = flag.String("ports", "", "ports to intercept (comma-separated, overrides config)")
		workers     = flag.Int("workers", -1, "number of workers (overrides config)")
		dumpConfig  = flag.Bool("dump-config", false, "dump default config to stdout")
		genConfig   = flag.String("gen-config", "", "generate default config file")
	)
	flag.Parse()

	// Показываем версию
	if *showVersion {
		fmt.Printf("ByPass version %s\n", version)
		fmt.Printf("  build time: %s\n", buildTime)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  go version: %s\n", runtime.Version())
		fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	// Генерируем конфигурацию по умолчанию
	if *dumpConfig {
		cfg := config.DefaultConfig()
		data, err := yaml.Marshal(cfg)
		if err != nil {
			log.Fatalf("Failed to marshal config: %v", err)
		}
		fmt.Println(string(data))
		return
	}

	// Генерируем файл конфигурации
	if *genConfig != "" {
		cfg := config.DefaultConfig()
		if err := cfg.Save(*genConfig); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		fmt.Printf("Default config saved to %s\n", *genConfig)
		return
	}

	// Загружаем конфигурацию
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Переопределяем параметры из командной строки
	if *queueNum >= 0 {
		cfg.Capture.QueueNum = *queueNum
	}
	if *ports != "" {
		cfg.Firewall.Ports = parsePorts(*ports)
	}
	if *workers > 0 {
		cfg.Pipeline.Workers = *workers
	}

	// Настраиваем логирование
	setupLogging(cfg.Logging)

	// Выводим информацию о запуске
	log.Printf("Starting %s version %s", cfg.App.Name, cfg.App.Version)
	log.Printf("  OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)
	log.Printf("  Config: queue=%d, ports=%v, workers=%d",
		cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Pipeline.Workers)

	// Создаем контекст для graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Инициализируем компоненты
	components, err := initializeComponents(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize components: %v", err)
	}
	defer components.cleanup()

	// Настраиваем файрвол
	if err := setupFirewall(cfg); err != nil {
		log.Fatalf("Failed to setup firewall: %v", err)
	}

	// Запускаем конвейер
	if err := components.pipeline.Start(); err != nil {
		log.Fatalf("Failed to start pipeline: %v", err)
	}

	// Запускаем авто-дискавери если нужно
	if cfg.Strategy.AutoDiscovery.Enabled {
		go runDiscovery(components.strategyMgr, cfg)
	}

	// Запускаем мониторинг статистики
	go runStatsMonitor(components)

	// Ожидаем сигнала завершения
	waitForShutdown()

	// Graceful shutdown
	log.Println("Shutting down...")
	components.pipeline.Stop()
	components.conntrack.Stop()
	components.strategyMgr.Stop()

	// Очищаем правила файрвола
	if cfg.Firewall.CleanupOnExit {
		cleanupFirewall(cfg)
	}

	log.Println("Shutdown complete")
}

// Components содержит все инициализированные компоненты
type Components struct {
	ipCache     *cache.IPCache
	domainCache *cache.DomainCache
	conntrack   *conntrack.Manager
	analyzer    *protocol.Analyzer
	strategyMgr *strategy.Manager
	modifier    *modifier.PacketModifier
	sender      sender.Sender
	capturer    capture.Capturer
	pipeline    *packetflow.Pipeline
}

// initializeComponents создает все необходимые компоненты
func initializeComponents(ctx context.Context, cfg *config.Config) (*Components, error) {
	// Кэши
	ipCache := cache.NewIPCache(
		cfg.Cache.IPCache.TTL,
		cfg.Cache.IPCache.MaxSize,
	)

	domainCache := cache.NewDomainCache(
		cfg.Cache.DomainCache.TTL,
		cfg.Cache.DomainCache.MaxSize,
	)

	// Предзагружаем популярные домены
	if len(cfg.Cache.DomainCache.Preload) > 0 {
		go domainCache.Preload(cfg.Cache.DomainCache.Preload)
	}

	// Менеджер потоков
	connManager := conntrack.NewManager(
		cfg.Conntrack.Timeout,
		cfg.Conntrack.MaxFlows,
	)

	// Анализатор протоколов
	analyzer := protocol.NewAnalyzer()

	// Менеджер стратегий
	strategyMgr := strategy.NewManager()
	if cfg.Strategy.StrategyFile != "" {
		if err := strategyMgr.LoadFromFile(cfg.Strategy.StrategyFile); err != nil {
			log.Printf("Warning: failed to load strategies from %s: %v",
				cfg.Strategy.StrategyFile, err)
		}
	}

	// Модификатор пакетов
	packetModifier := modifier.NewPacketModifier(strategyMgr, ipCache)

	// Отправитель
	sender, err := sender.NewSender(sender.Config{
		Interface:   cfg.Sender.Interface,
		BufferSize:  cfg.Sender.BufferSize,
		SendTimeout: cfg.Sender.SendTimeout,
		BatchSize:   cfg.Sender.BatchSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sender: %v", err)
	}

	// Захватчик - используем фабричный метод вместо прямого вызова NewNFQueue
	var capturer capture.Capturer

	// В зависимости от платформы создаем соответствующий захватчик
	capturer, err = capture.New(capture.Config{
		QueueNum:     cfg.Capture.QueueNum,
		BufferSize:   cfg.Capture.BufferSize,
		Interface:    cfg.Capture.Interface,
		MaxPacketLen: cfg.Capture.MaxPacketLen,
	})

	if err != nil {
		sender.Close()
		return nil, fmt.Errorf("failed to create capturer: %v", err)
	}

	// Конвейер
	pipeline := packetflow.NewPipeline(
		capturer,
		connManager,
		packetModifier,
		sender,
		analyzer,
		ipCache,
		domainCache,
		strategyMgr,
		packetflow.Config{
			Workers:         cfg.Pipeline.Workers,
			PacketQueueSize: cfg.Pipeline.PacketQueueSize,
			ResultQueueSize: cfg.Pipeline.ResultQueueSize,
			ProcessTimeout:  cfg.Pipeline.ProcessTimeout,
		},
	)

	return &Components{
		ipCache:     ipCache,
		domainCache: domainCache,
		conntrack:   connManager,
		analyzer:    analyzer,
		strategyMgr: strategyMgr,
		modifier:    packetModifier,
		sender:      sender,
		capturer:    capturer,
		pipeline:    pipeline,
	}, nil
}

// cleanup освобождает ресурсы
func (c *Components) cleanup() {
	if c.sender != nil {
		c.sender.Close()
	}
	if c.capturer != nil {
		c.capturer.Stop()
	}
}

// setupFirewall настраивает правила файрвола
func setupFirewall(cfg *config.Config) error {
	fw, err := firewall.NewManager(firewall.Config{
		Backend:       cfg.Firewall.Backend,
		QueueNum:      cfg.Capture.QueueNum,
		Ports:         cfg.Firewall.Ports,
		Direction:     cfg.Firewall.Direction,
		ExcludeIPs:    cfg.Firewall.ExcludeIPs,
		ExcludePorts:  cfg.Firewall.ExcludePorts,
		CleanupOnExit: cfg.Firewall.CleanupOnExit,
	})
	if err != nil {
		return err
	}

	return fw.AddRule(cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Firewall.Direction)
}

// cleanupFirewall удаляет правила файрвола
func cleanupFirewall(cfg *config.Config) {
	fw, err := firewall.NewManager(firewall.Config{
		Backend:  cfg.Firewall.Backend,
		QueueNum: cfg.Capture.QueueNum,
		Ports:    cfg.Firewall.Ports,
	})
	if err != nil {
		log.Printf("Failed to create firewall manager for cleanup: %v", err)
		return
	}

	if err := fw.RemoveRule(cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Firewall.Direction); err != nil {
		log.Printf("Failed to cleanup firewall rules: %v", err)
	}
}

// setupLogging настраивает логирование
func setupLogging(cfg config.LoggingConfig) {
	// Здесь можно настроить более продвинутое логирование
	// Например, через logrus или zap
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	if cfg.Output == "file" && cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.SetOutput(f)
		}
	}
}

// runDiscovery запускает авто-подбор стратегий
func runDiscovery(strategyMgr *strategy.Manager, cfg *config.Config) {
	discovery := strategy.NewDiscovery(strategyMgr, strategy.DiscoveryConfig{
		TestDomains:    cfg.Strategy.AutoDiscovery.TestDomains,
		TestPorts:      cfg.Strategy.AutoDiscovery.TestPorts,
		TestTimeout:    5 * time.Second,
		TestInterval:   time.Duration(cfg.Strategy.AutoDiscovery.TestInterval) * time.Second,
		SamplesPerTest: 5,
		MinSuccessRate: cfg.Strategy.AutoDiscovery.MinSuccessRate,
	})

	log.Println("Starting auto-discovery...")
	if err := discovery.Start(); err != nil {
		log.Printf("Auto-discovery error: %v", err)
		return
	}

	// Периодически проверяем результаты
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		results := discovery.GetResults()
		if len(results) > 0 {
			best := results[0]
			log.Printf("Auto-discovery: best strategy %d with success rate %.1f%%",
				best.StrategyID, best.SuccessRate*100)

			if best.SuccessRate >= cfg.Strategy.AutoDiscovery.MinSuccessRate {
				discovery.ApplyBestStrategy()
				break
			}
		}
	}
}

// runStatsMonitor выводит статистику работы
func runStatsMonitor(components *Components) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Статистика конвейера
		pipelineStats := components.pipeline.GetStats()

		// Статистика потоков
		connStats := components.conntrack.GetStats()

		// Статистика кэша
		ipCacheStats := components.ipCache.GetStats()
		domainCacheStats := components.domainCache.GetStats()

		log.Printf("Stats:"+
			" packets: recv=%d proc=%d mod=%d sent=%d drop=%d |"+
			" flows: active=%d total=%d |"+
			" cache: ip=%d dom=%d hits=%d misses=%d",
			pipelineStats.PacketsReceived,
			pipelineStats.PacketsProcessed,
			pipelineStats.PacketsModified,
			pipelineStats.PacketsSent,
			pipelineStats.PacketsDropped,
			connStats.ActiveFlows,
			connStats.CreatedFlows,
			ipCacheStats.Size,
			domainCacheStats.Size,
			pipelineStats.CacheHits,
			pipelineStats.CacheMisses,
		)
	}
}

// waitForShutdown ожидает сигнала завершения
func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

// parsePorts парсит строку с портами
func parsePorts(portsStr string) []int {
	if portsStr == "" {
		return nil
	}

	var ports []int
	for _, p := range strings.Split(portsStr, ",") {
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	return ports
}
