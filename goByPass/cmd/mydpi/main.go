package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
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

	if *showVersion {
		fmt.Printf("ByPass version %s\n", version)
		fmt.Printf("  build time: %s\n", buildTime)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  go version: %s\n", runtime.Version())
		fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	if *dumpConfig {
		cfg := config.DefaultConfig()
		data, err := yaml.Marshal(cfg)
		if err != nil {
			log.Fatalf("Failed to marshal config: %v", err)
		}
		fmt.Println(string(data))
		return
	}

	if *genConfig != "" {
		cfg := config.DefaultConfig()
		if err := cfg.Save(*genConfig); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		fmt.Printf("Default config saved to %s\n", *genConfig)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *queueNum >= 0 {
		cfg.Capture.QueueNum = *queueNum
	}
	if *ports != "" {
		parsedPorts, err := parsePorts(*ports)
		if err != nil {
			log.Fatalf("Invalid --ports value: %v", err)
		}
		cfg.Firewall.Ports = parsedPorts
	}
	if *workers > 0 {
		cfg.Pipeline.Workers = *workers
	}

	// Повторно валидируем конфиг после CLI overrides.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration after CLI overrides: %v", err)
	}

	logFile := setupLogging(cfg.Logging)

	log.Printf("Starting %s version %s", cfg.App.Name, cfg.App.Version)
	log.Printf("  OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)
	log.Printf("  Config: queue=%d, ports=%v, workers=%d",
		cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Pipeline.Workers)

	if cfg.Strategy.DefaultStrategy != "" {
		log.Printf("WARNING: strategy.default_strategy=%q is currently informational only; runtime selection is still direct-by-default + hostname rules", cfg.Strategy.DefaultStrategy)
	}

	if !cfg.Cache.IPCache.Enabled {
		log.Printf("WARNING: cache.ip_cache.enabled=false is not fully implemented yet; IPCache will still be created")
	}
	if !cfg.Cache.DomainCache.Enabled {
		log.Printf("WARNING: cache.domain_cache.enabled=false is not fully implemented yet; DomainCache will still be created")
	}
	if cfg.Sender.Type != "" && cfg.Sender.Type != "raw" {
		log.Printf("WARNING: sender.type=%q is not used by initializeComponents; raw sender will still be created", cfg.Sender.Type)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	components, err := initializeComponents(ctx, cfg)
	if err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		log.Printf("Failed to initialize components: %v", err)
		os.Exit(1)
	}
	components.logFile = logFile

	cleanupOnError := func() {
		if components.pipeline != nil {
			components.pipeline.Stop()
		}
		if components.conntrack != nil {
			components.conntrack.Stop()
		}
		if components.strategyMgr != nil {
			components.strategyMgr.Stop()
		}
		if components.firewall != nil {
			_ = components.firewall.RemoveRule(cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Firewall.Direction)
		}
		components.cleanup()
	}

	// Firewall в components
	if err := components.firewall.AddRule(cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Firewall.Direction); err != nil {
		log.Printf("Failed to setup firewall: %v", err)
		cleanupOnError()
		os.Exit(1)
	}

	if err := components.pipeline.Start(); err != nil {
		log.Printf("Failed to start pipeline: %v", err)
		cleanupOnError()
		os.Exit(1)
	}

	// Запускаем авто-дискавери если нужно.
	// Hostname rules имеют приоритет: discovery только для доменов,
	// для которых нет явного правила в cfg.Strategy.HostnameRules.
	if cfg.Strategy.AutoDiscovery.Enabled {
		log.Printf("[Discovery] AutoDiscovery is configured, but automatic background discovery is disabled in normal runtime because it mutates live traffic via test overrides")
	}

	go runStatsMonitor(ctx, components)

	waitForShutdown()
	cancel()

	log.Println("Shutting down...")

	if components.pipeline != nil {
		components.pipeline.Stop()
	}
	if components.conntrack != nil {
		components.conntrack.Stop()
	}
	if components.strategyMgr != nil {
		components.strategyMgr.Stop()
	}
	if cfg.Firewall.CleanupOnExit && components.firewall != nil {
		_ = components.firewall.RemoveRule(cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Firewall.Direction)
	}

	components.cleanup()

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
	firewall    firewall.Manager
	logFile     *os.File
	queueNum    int
	ports       []int
	direction   string
}

// initializeComponents создает все необходимые компоненты
func initializeComponents(ctx context.Context, cfg *config.Config) (components *Components, err error) {
	components = &Components{}

	defer func() {
		if err == nil || components == nil {
			return
		}
		if components.pipeline != nil {
			components.pipeline.Stop()
		}
		if components.capturer != nil {
			_ = components.capturer.Stop()
		}
		if components.sender != nil {
			_ = components.sender.Close()
		}
		if components.conntrack != nil {
			components.conntrack.Stop()
		}
		if components.strategyMgr != nil {
			components.strategyMgr.Stop()
		}
		if components.ipCache != nil {
			components.ipCache.Stop()
		}
		if components.domainCache != nil {
			components.domainCache.Stop()
		}
		if components.firewall != nil && cfg.Firewall.CleanupOnExit {
			_ = components.firewall.RemoveRule(cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Firewall.Direction)
		}
		if components.logFile != nil {
			_ = components.logFile.Close()
		}
	}()

	ipCache := cache.NewIPCache(
		cfg.Cache.IPCache.TTL,
		cfg.Cache.IPCache.MaxSize,
	)
	components.ipCache = ipCache

	domainCache := cache.NewDomainCache(
		cfg.Cache.DomainCache.TTL,
		cfg.Cache.DomainCache.MaxSize,
	)
	components.domainCache = domainCache
	if len(cfg.Cache.DomainCache.Preload) > 0 {
		// Preload уже запускает горутины внутри (semaphore, до 5 одновременно).
		// Вызываем без внешнего `go` — иначе double goroutine spawn.
		if err := domainCache.Preload(cfg.Cache.DomainCache.Preload); err != nil {
			log.Printf("WARNING: domain cache preload failed: %v", err)
		}
	}

	connManager := conntrack.NewManager(
		cfg.Conntrack.Timeout,
		cfg.Conntrack.MaxFlows,
	)
	analyzer := protocol.NewAnalyzer()

	// Менеджер стратегий: сначала встроенные, затем из файла (если задан).
	// LoadFromFile добавляет/обновляет стратегии по ID — встроенные не удаляются.
	strategyMgr := strategy.NewManager()

	if cfg.Strategy.StrategyFile != "" {
		// сначала merge из JSON
		if err := strategyMgr.LoadFromFile(cfg.Strategy.StrategyFile); err != nil {
			log.Printf("Failed to load strategies from file: %v", err)
		} else {
			log.Printf("Loaded strategies from %s", cfg.Strategy.StrategyFile)
		}

		// и только теперь проверяем, какие стратегии реально активны
		if s, ok := strategyMgr.GetStrategy(12); ok {
			log.Printf("[DEBUG] ACTIVE strategy12: SplitSNIOffset=%v TLSRecordSplit=%v ModifyFirstDataPackets=%d",
				s.SplitSNIOffset, s.TLSRecordSplit, s.ModifyFirstDataPackets)
		}
		if s, ok := strategyMgr.GetStrategy(26); ok {
			log.Printf("[DEBUG] ACTIVE strategy26: MultiDisorder=%v ModifyFirstDataPackets=%d",
				s.MultiDisorder, s.ModifyFirstDataPackets)
		}
	}

	// Runtime asset'ы (.bin) живут отдельно от JSON-описания стратегий.
	// Сначала грузим их с диска, потом уже валидируем.
	assetBaseDir := "configs/strategies"
	if strings.TrimSpace(cfg.Strategy.StrategyFile) != "" {
		assetBaseDir = filepath.Dir(cfg.Strategy.StrategyFile)
	}

	if err := strategyMgr.LoadRuntimeAssets(assetBaseDir); err != nil {
		return components, fmt.Errorf("failed to load strategy runtime assets from %s: %w", assetBaseDir, err)
	}

	// Fail-fast: если стратегия ссылается на asset'ы, но runtime-данные всё ещё пустые,
	// лучше упасть на старте, чем silently ломать handshake/QUIC.
	if err := strategyMgr.ValidateRuntimeAssets(); err != nil {
		return components, fmt.Errorf("strategy runtime assets validation failed: %w", err)
	}

	// ── Hostname Rules ────────────────────────────────────────────────────────
	// Статические правила hostname→strategy загружаются ОДИН РАЗ при старте.
	// Они имеют абсолютный приоритет над IP-кэшем, fallback и discovery.
	// Это решает проблему «всегда выбирается стратегия 40»: правила гарантируют
	// что youtube.com → нужная стратегия независимо от порядка выборки.
	//
	// cfg.Strategy.HostnameRules — []config.HostnameRuleConfig (не strategy.HostnameRule)
	// во избежание циклического импорта config↔strategy.
	// Конвертируем в []strategy.HostnameRule здесь, в main.go.
	var stratRules []strategy.HostnameRule
	if len(cfg.Strategy.HostnameRules) > 0 {
		stratRules = make([]strategy.HostnameRule, 0, len(cfg.Strategy.HostnameRules))
		for _, r := range cfg.Strategy.HostnameRules {
			stratRules = append(stratRules, strategy.HostnameRule{
				Pattern:      r.Pattern,
				StrategyName: r.Strategy,
				StrategyID:   r.StrategyID,
				Comment:      r.Comment,
			})
		}
		log.Printf("Using hostname rules from config (%d rules)", len(stratRules))
	} else {
		stratRules = defaultHostnameRules()
		log.Printf("Using built-in hostname rules (%d rules)", len(stratRules))
	}
	strategyMgr.SetHostnameRules(stratRules)

	packetModifier := modifier.NewPacketModifier(strategyMgr, ipCache)

	var s sender.Sender
	s, err = sender.NewSender(sender.Config{
		Interface:   cfg.Sender.Interface,
		BufferSize:  cfg.Sender.BufferSize,
		SendTimeout: cfg.Sender.SendTimeout,
		BatchSize:   cfg.Sender.BatchSize,
	})
	if err != nil {
		log.Printf("Failed to create sender: %v", err)
		return nil, err
	}

	capturer, err := capture.New(capture.Config{
		QueueNum:     cfg.Capture.QueueNum,
		BufferSize:   cfg.Capture.BufferSize,
		Interface:    cfg.Capture.Interface,
		MaxPacketLen: cfg.Capture.MaxPacketLen,
	})
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to create capturer: %v", err)
	}

	if err := capturer.Start(ctx); err != nil {
		s.Close()
		capturer.Stop()
		return nil, fmt.Errorf("failed to start capturer: %v", err)
	}

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
		return nil, fmt.Errorf("failed to create firewall manager: %v", err)
	}

	pipeline := packetflow.NewPipeline(
		capturer,
		connManager,
		packetModifier,
		s,
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

	components.conntrack = connManager
	components.analyzer = analyzer
	components.strategyMgr = strategyMgr
	components.modifier = packetModifier
	components.sender = s
	components.capturer = capturer
	components.firewall = fw
	components.pipeline = pipeline

	return components, nil
}

// defaultHostnameRules возвращает встроенные правила hostname→strategy.
//
// Правила применяются ДО выбора по IP и дефолтного fallback.
// Порядок: первое совпадение побеждает.
func defaultHostnameRules() []strategy.HostnameRule {
	return []strategy.HostnameRule{
		// Core YouTube endpoints only
		{Pattern: "*.youtube.com", StrategyName: "youtube-2026", Comment: "YouTube"},
		{Pattern: "youtube.com", StrategyName: "youtube-2026", Comment: "YouTube bare"},
		{Pattern: "accounts.youtube.com", StrategyName: "youtube-2026", Comment: "YouTube accounts"},
		{Pattern: "*.googlevideo.com", StrategyName: "youtube-2026", Comment: "YouTube video CDN"},
		{Pattern: "*.youtubei.googleapis.com", StrategyName: "youtube-2026", Comment: "YouTube API"},
		{Pattern: "*.youtube-nocookie.com", StrategyName: "youtube-2026", Comment: "YouTube embed"},

		// Static / avatars / telemetry — не форсируем bypass по умолчанию
		{Pattern: "*.ytimg.com", StrategyName: "youtube-2026", Comment: "YouTube static"},
		{Pattern: "*.ggpht.com", StrategyName: "youtube-2026", Comment: "Google avatars/images"},
		{Pattern: "*.gvt1.com", StrategyName: "passthrough", Comment: "GVT passthrough"},
		{Pattern: "*.gvt2.com", StrategyName: "passthrough", Comment: "GVT passthrough"},

		// Discord
		{Pattern: "*.discord.com", StrategyName: "discord-2026", Comment: "Discord"},
		{Pattern: "discord.com", StrategyName: "discord-2026", Comment: "Discord bare"},
		{Pattern: "*.discordapp.com", StrategyName: "discord-2026", Comment: "Discord CDN"},
		{Pattern: "*.discord.gg", StrategyName: "discord-2026", Comment: "Discord invite"},
		{Pattern: "*.discord.media", StrategyName: "discord-2026", Comment: "Discord media"},

		// Telegram
		{Pattern: "*.telegram.org", StrategyName: "telegram", Comment: "Telegram Web"},
		{Pattern: "telegram.org", StrategyName: "telegram", Comment: "Telegram bare"},
		{Pattern: "*.t.me", StrategyName: "telegram", Comment: "Telegram short links"},
		{Pattern: "t.me", StrategyName: "telegram", Comment: "Telegram t.me"},

		// Twitter/X
		{Pattern: "*.twitter.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Twitter/X"},
		{Pattern: "*.x.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "X (Twitter)"},
		{Pattern: "*.twimg.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Twitter images/media"},

		// Прочие часто замедляемые
		{Pattern: "*.twitch.tv", StrategyName: "yt-discord-2026-zapret",
			Comment: "Twitch стримы"},
		{Pattern: "*.soundcloud.com", StrategyName: "medium",
			Comment: "SoundCloud"},
		{Pattern: "*.spotify.com", StrategyName: "medium",
			Comment: "Spotify"},
	}
}

// cleanup освобождает ресурсы
func (c *Components) cleanup() {
	if c.ipCache != nil {
		c.ipCache.Stop()
	}
	if c.domainCache != nil {
		c.domainCache.Stop()
	}
	if c.logFile != nil {
		_ = c.logFile.Close()
	}
}

// setupLogging настраивает логирование
func setupLogging(cfg config.LoggingConfig) *os.File {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	if cfg.Output == "file" && cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("WARNING: failed to open log file %s: %v", cfg.FilePath, err)
			return nil
		}
		log.SetOutput(f)
		return f
	}

	return nil
}

// runManualDiscovery запускает авто-подбор стратегий.
//
// Discovery тестирует только домены из cfg.Strategy.AutoDiscovery.TestDomains.
// Для доменов, которые уже покрыты hostname rules (defaultHostnameRules),
// discovery НЕ нужен — он только перегружает сеть.
//
// После нахождения стратегии с достаточным success rate:
//   - Применяем лучшую стратегию через ApplyBestStrategy
//   - Обновляем hostname rule для тестируемого домена (если он там есть)
//   - Продолжаем мониторинг — пересматриваем каждые 5 минут
func runManualDiscovery(strategyMgr *strategy.Manager, cfg *config.Config) {
	var disc *strategy.Discovery
	restart := func() {
		if disc != nil {
			disc.Stop()
			time.Sleep(100 * time.Millisecond) // даём Stop() завершить wg
		}
		disc = strategy.NewDiscovery(strategyMgr, strategy.DiscoveryConfig{
			TestDomains:    cfg.Strategy.AutoDiscovery.TestDomains,
			TestPorts:      cfg.Strategy.AutoDiscovery.TestPorts,
			TestTimeout:    5 * time.Second,
			TestInterval:   time.Duration(cfg.Strategy.AutoDiscovery.TestInterval) * time.Second,
			SamplesPerTest: 5,
			MinSuccessRate: cfg.Strategy.AutoDiscovery.MinSuccessRate,
		})
		if err := disc.Start(); err != nil {
			log.Printf("[Discovery] Start error: %v", err)
		}
	}

	restart()

	restartTicker := time.NewTicker(5 * time.Minute)
	defer restartTicker.Stop()

	for range restartTicker.C {
		log.Printf("[Discovery] Restarting cycle...")
		restart()
	}
}

// runStatsMonitor выводит статистику работы
func runStatsMonitor(ctx context.Context, components *Components) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pipelineStats := components.pipeline.GetStats()
			connStats := components.conntrack.GetStats()
			ipCacheStats := components.ipCache.GetStats()
			domainCacheStats := components.domainCache.GetStats()

			modRate := float64(0)
			if pipelineStats.PacketsProcessed > 0 {
				modRate = float64(pipelineStats.PacketsModified) / float64(pipelineStats.PacketsProcessed) * 100
			}

			log.Printf("[Stats] pkts: recv=%d proc=%d mod=%d(%.0f%%) sent=%d drop=%d | flows: active=%d total=%d | cache: ip=%d dom=%d hits=%d miss=%d",
				pipelineStats.PacketsReceived,
				pipelineStats.PacketsProcessed,
				pipelineStats.PacketsModified,
				modRate,
				pipelineStats.PacketsSent,
				pipelineStats.PacketsDropped,
				connStats.ActiveFlows,
				connStats.CreatedFlows,
				ipCacheStats.Size,
				domainCacheStats.Size,
				pipelineStats.CacheHits,
				pipelineStats.CacheMisses,
			)
		case <-ctx.Done():
			return
		}
	}
}

// waitForShutdown ожидает сигнала завершения
func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			log.Println("SIGHUP received — config reload not yet implemented")
			// TODO: full reload
			continue
		}
		log.Printf("Received signal: %v", sig)
		return
	}
}

// parsePorts парсит строку с портами
func parsePorts(portsStr string) ([]int, error) {
	if strings.TrimSpace(portsStr) == "" {
		return nil, fmt.Errorf("empty ports string")
	}

	var ports []int
	for _, raw := range strings.Split(portsStr, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			return nil, fmt.Errorf("empty port entry")
		}

		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}

		ports = append(ports, port)
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports provided")
	}

	return ports, nil
}
