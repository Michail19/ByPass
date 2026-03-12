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
		cfg.Firewall.Ports = parsePorts(*ports)
	}
	if *workers > 0 {
		cfg.Pipeline.Workers = *workers
	}

	setupLogging(cfg.Logging)

	log.Printf("Starting %s version %s", cfg.App.Name, cfg.App.Version)
	log.Printf("  OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH)
	log.Printf("  Config: queue=%d, ports=%v, workers=%d",
		cfg.Capture.QueueNum, cfg.Firewall.Ports, cfg.Pipeline.Workers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	components, err := initializeComponents(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize components: %v", err)
	}
	defer components.cleanup()

	if err := setupFirewall(cfg); err != nil {
		log.Fatalf("Failed to setup firewall: %v", err)
	}

	if err := components.pipeline.Start(); err != nil {
		log.Fatalf("Failed to start pipeline: %v", err)
	}

	// Запускаем авто-дискавери если нужно.
	// Hostname rules имеют приоритет: discovery только для доменов,
	// для которых нет явного правила в cfg.Strategy.HostnameRules.
	if cfg.Strategy.AutoDiscovery.Enabled {
		go runDiscovery(components.strategyMgr, cfg)
	}

	go runStatsMonitor(components)

	waitForShutdown()

	log.Println("Shutting down...")
	components.pipeline.Stop()
	components.conntrack.Stop()
	components.strategyMgr.Stop()

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
	ipCache := cache.NewIPCache(
		cfg.Cache.IPCache.TTL,
		cfg.Cache.IPCache.MaxSize,
	)
	domainCache := cache.NewDomainCache(
		cfg.Cache.DomainCache.TTL,
		cfg.Cache.DomainCache.MaxSize,
	)
	if len(cfg.Cache.DomainCache.Preload) > 0 {
		// Preload уже запускает горутины внутри (semaphore, до 5 одновременно).
		// Вызываем без внешнего `go` — иначе double goroutine spawn.
		domainCache.Preload(cfg.Cache.DomainCache.Preload)
	}

	connManager := conntrack.NewManager(
		cfg.Conntrack.Timeout,
		cfg.Conntrack.MaxFlows,
	)
	analyzer := protocol.NewAnalyzer()

	// Менеджер стратегий: сначала встроенные, затем из файла (если задан).
	// LoadFromFile добавляет/обновляет стратегии по ID — встроенные не удаляются.
	strategyMgr := strategy.NewManager()

	if err := strategyMgr.LoadPatternFiles("patterns"); err != nil { // или куда у тебя .bin лежат
		log.Printf("Warning: %v", err)
	}

	if cfg.Strategy.StrategyFile != "" {
		if err := strategyMgr.LoadFromFile(cfg.Strategy.StrategyFile); err != nil {
			log.Printf("Warning: failed to load strategies from %s: %v",
				cfg.Strategy.StrategyFile, err)
		} else {
			log.Printf("Loaded strategies from %s", cfg.Strategy.StrategyFile)
		}
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
	s, err := sender.NewSender(sender.Config{
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

	handle := capturer.GetHandle()
	log.Printf("DEBUG: Got handle from capturer after Start: %v", handle)

	if handle != 0 {
		if _, ok := s.(*sender.RawSender); ok {
			s.Close()
			s, err = sender.NewSenderWithHandle(handle, sender.Config{
				Interface:   cfg.Sender.Interface,
				BufferSize:  cfg.Sender.BufferSize,
				SendTimeout: cfg.Sender.SendTimeout,
				BatchSize:   cfg.Sender.BatchSize,
			})
			if err != nil {
				capturer.Stop()
				return nil, fmt.Errorf("failed to create sender with shared handle: %v", err)
			}
			log.Printf("Using WinDivert sender with shared handle: %v", handle)
		}
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

	return &Components{
		ipCache:     ipCache,
		domainCache: domainCache,
		conntrack:   connManager,
		analyzer:    analyzer,
		strategyMgr: strategyMgr,
		modifier:    packetModifier,
		sender:      s,
		capturer:    capturer,
		pipeline:    pipeline,
	}, nil
}

// defaultHostnameRules возвращает встроенные правила hostname→strategy.
//
// Правила применяются ДО выбора по IP и дефолтного fallback.
// Порядок: первое совпадение побеждает.
//
// Источники для паттернов:
//   - Наш захват wireshark показал основные цели: youtube.com + субдомены,
//     googleads, ytimg, ggpht, doubleclick, gstatic.
//   - Discord и другие цели добавлены из типичных сценариев ТСПУ.
//
// Стратегии выбраны как наиболее эффективные для ТСПУ 2026 (multisplit seqovl=681):
//   - YouTube/Google → "yt-discord-2026-zapret" (multisplit+fake×6+QUIC)
//   - Discord        → "discord-2026" (split+TLS record split)
//   - Telegram       → "telegram" (split+TLS record split)
//
// Для остальных доменов SelectStrategy делает обычный fallback по приоритету.
func defaultHostnameRules() []strategy.HostnameRule {
	return []strategy.HostnameRule{
		// ── YouTube и Google Video ────────────────────────────────────────────
		{Pattern: "*.youtube.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "YouTube основной домен"},
		{Pattern: "youtube.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "YouTube bare domain"},
		{Pattern: "*.ytimg.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "YouTube thumbnails/images"},
		{Pattern: "*.ggpht.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "YouTube аватары/фото"},
		{Pattern: "*.googlevideo.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "YouTube видеопоток"},
		{Pattern: "*.youtube-nocookie.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "YouTube embed"},

		// ── Google (остальные) ────────────────────────────────────────────────
		{Pattern: "*.googleapis.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Google APIs (используются YouTube)"},
		{Pattern: "*.gstatic.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Google static (шрифты, ресурсы)"},
		{Pattern: "*.doubleclick.net", StrategyName: "yt-discord-2026-zapret",
			Comment: "Google Ads (наш захват показал 9 подключений)"},
		{Pattern: "*.google.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Google основной"},
		{Pattern: "*.googleusercontent.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Google User Content"},

		// ── Discord ───────────────────────────────────────────────────────────
		{Pattern: "*.discord.com", StrategyName: "discord-2026",
			Comment: "Discord основной"},
		{Pattern: "discord.com", StrategyName: "discord-2026",
			Comment: "Discord bare"},
		{Pattern: "*.discordapp.com", StrategyName: "discord-2026",
			Comment: "Discord CDN/assets"},
		{Pattern: "*.discord.gg", StrategyName: "discord-2026",
			Comment: "Discord invite links"},
		{Pattern: "*.discord.media", StrategyName: "discord-2026",
			Comment: "Discord медиа"},

		// ── Telegram ──────────────────────────────────────────────────────────
		// Наш захват содержит 149.154.167.99 (Telegram DC1)
		{Pattern: "*.telegram.org", StrategyName: "telegram",
			Comment: "Telegram Web"},
		{Pattern: "telegram.org", StrategyName: "telegram",
			Comment: "Telegram bare"},
		{Pattern: "*.t.me", StrategyName: "telegram",
			Comment: "Telegram short links"},
		{Pattern: "t.me", StrategyName: "telegram",
			Comment: "Telegram t.me"},
		{Pattern: "*.tdesktop.com", StrategyName: "telegram",
			Comment: "Telegram Desktop updates"},

		// ── Instagram / Meta ──────────────────────────────────────────────────
		{Pattern: "*.instagram.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Instagram"},
		{Pattern: "*.cdninstagram.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Instagram CDN"},
		{Pattern: "*.facebook.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Facebook"},

		// ── Twitter/X ─────────────────────────────────────────────────────────
		{Pattern: "*.twitter.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Twitter/X"},
		{Pattern: "*.x.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "X (Twitter)"},
		{Pattern: "*.twimg.com", StrategyName: "yt-discord-2026-zapret",
			Comment: "Twitter images/media"},

		// ── Прочие часто замедляемые ──────────────────────────────────────────
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
	if c.sender != nil {
		c.sender.Close()
	}
	if c.capturer != nil {
		c.capturer.Stop()
	}
	// FIX: остановить фоновые goroutine кэшей.
	// Без Stop() cleanupLoop() работает вечно через time.NewTicker — goroutine leak.
	if c.ipCache != nil {
		c.ipCache.Stop()
	}
	if c.domainCache != nil {
		c.domainCache.Stop()
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
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	if cfg.Output == "file" && cfg.FilePath != "" {
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.SetOutput(f)
		}
	}
}

// runDiscovery запускает авто-подбор стратегий.
//
// Discovery тестирует только домены из cfg.Strategy.AutoDiscovery.TestDomains.
// Для доменов, которые уже покрыты hostname rules (defaultHostnameRules),
// discovery НЕ нужен — он только перегружает сеть.
//
// После нахождения стратегии с достаточным success rate:
//   - Применяем лучшую стратегию через ApplyBestStrategy
//   - Обновляем hostname rule для тестируемого домена (если он там есть)
//   - Продолжаем мониторинг — пересматриваем каждые 5 минут
func runDiscovery(strategyMgr *strategy.Manager, cfg *config.Config) {
	disc := strategy.NewDiscovery(strategyMgr, strategy.DiscoveryConfig{
		TestDomains:    cfg.Strategy.AutoDiscovery.TestDomains,
		TestPorts:      cfg.Strategy.AutoDiscovery.TestPorts,
		TestTimeout:    5 * time.Second,
		TestInterval:   time.Duration(cfg.Strategy.AutoDiscovery.TestInterval) * time.Second,
		SamplesPerTest: 5,
		MinSuccessRate: cfg.Strategy.AutoDiscovery.MinSuccessRate,
	})

	log.Printf("[Discovery] Starting auto-discovery for domains: %v", cfg.Strategy.AutoDiscovery.TestDomains)
	if err := disc.Start(); err != nil {
		log.Printf("[Discovery] Start error: %v", err)
		return
	}

	// Ждём завершения первого прогона (~SamplesPerTest × TestInterval × стратегий)
	// Тикер проверяет прогресс каждые 15 секунд.
	checkTicker := time.NewTicker(15 * time.Second)
	defer checkTicker.Stop()

	// Перезапуск discovery каждые 5 минут — реакция на смену условий сети.
	restartTicker := time.NewTicker(5 * time.Minute)
	defer restartTicker.Stop()

	applied := false // нашли хорошую стратегию хотя бы раз

	for {
		select {
		case <-checkTicker.C:
			results := disc.GetResults()
			if len(results) == 0 {
				continue
			}

			progress := disc.GetProgress()
			pct := float64(0)
			if progress.TotalTests > 0 {
				pct = float64(progress.CompletedTests) / float64(progress.TotalTests) * 100
			}
			log.Printf("[Discovery] Progress: %.0f%% (%d/%d tests), best so far: id=%d rate=%.0f%%",
				pct,
				progress.CompletedTests,
				progress.TotalTests,
				results[0].StrategyID,
				results[0].SuccessRate*100,
			)

			best := disc.GetBestStrategy()
			if best != nil && best.SuccessRate >= cfg.Strategy.AutoDiscovery.MinSuccessRate {
				if err := disc.ApplyBestStrategy(); err == nil {
					if !applied {
						log.Printf("[Discovery] Applied best strategy: id=%d, rate=%.0f%%, avg=%v",
							best.StrategyID, best.SuccessRate*100, best.AvgResponse)
						applied = true
					}
				}
			}

		case <-restartTicker.C:
			// Перезапускаем — условия сети могли измениться
			disc.Stop()
			applied = false
			log.Printf("[Discovery] Restarting discovery cycle...")
			disc = strategy.NewDiscovery(strategyMgr, strategy.DiscoveryConfig{
				TestDomains:    cfg.Strategy.AutoDiscovery.TestDomains,
				TestPorts:      cfg.Strategy.AutoDiscovery.TestPorts,
				TestTimeout:    5 * time.Second,
				TestInterval:   time.Duration(cfg.Strategy.AutoDiscovery.TestInterval) * time.Second,
				SamplesPerTest: 5,
				MinSuccessRate: cfg.Strategy.AutoDiscovery.MinSuccessRate,
			})
			if err := disc.Start(); err != nil {
				log.Printf("[Discovery] Restart error: %v", err)
			}
		}
	}
}

// runStatsMonitor выводит статистику работы
func runStatsMonitor(components *Components) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
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
	}
}

// waitForShutdown ожидает сигнала завершения
func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("Received signal: %v", sig)
}

// parsePorts парсит строку с портами
func parsePorts(portsStr string) []int {
	if portsStr == "" {
		return nil
	}
	var ports []int
	for _, p := range strings.Split(portsStr, ",") {
		var port int
		if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &port); err == nil && port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	return ports
}
