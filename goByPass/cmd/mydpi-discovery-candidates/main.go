package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ByPass/internal/config"
	"ByPass/internal/strategy"
)

func main() {
	var (
		configFile    = flag.String("config", "", "path to config file")
		domains       = flag.String("domains", "", "comma-separated domains to probe")
		output        = flag.String("output", "candidate-discovery-report.json", "output report file")
		samples       = flag.Int("samples", 3, "number of probe samples per candidate/domain/protocol")
		timeout       = flag.Duration("timeout", 5*time.Second, "timeout per probe")
		interval      = flag.Duration("interval", 150*time.Millisecond, "base delay between probes")
		maxCandidates = flag.Int("max-candidates", 64, "maximum generated candidates")
	)
	flag.Parse()

	cfg := loadConfig(*configFile)

	sm := strategy.NewManager()
	defer sm.Stop()

	if cfg.Strategy.StrategyFile != "" {
		if err := sm.LoadFromFile(cfg.Strategy.StrategyFile); err != nil {
			log.Printf("warning: failed to load strategies from %s: %v", cfg.Strategy.StrategyFile, err)
		}
	}

	assetsDir := inferAssetsDir(cfg.Strategy.StrategyFile)
	if err := sm.LoadRuntimeAssets(assetsDir); err != nil {
		log.Printf("warning: failed to load runtime assets from %s: %v", assetsDir, err)
	}
	if err := sm.ValidateRuntimeAssets(); err != nil {
		log.Printf("warning: runtime assets validation failed: %v", err)
	}

	testDomains := parseList(*domains)
	if len(testDomains) == 0 {
		testDomains = cfg.Strategy.AutoDiscovery.TestDomains
	}
	if len(testDomains) == 0 {
		testDomains = []string{"youtube.com", "googlevideo.com", "discord.com", "telegram.org", "github.com"}
	}

	runner := strategy.NewCandidateDiscoveryRunner(sm, strategy.CandidateDiscoveryConfig{
		Domains:       testDomains,
		Timeout:       *timeout,
		Interval:      *interval,
		Samples:       *samples,
		MaxCandidates: *maxCandidates,
	})

	fmt.Printf("Starting candidate discovery for %d domains, up to %d candidates, %d samples each\n", len(testDomains), *maxCandidates, *samples)
	ctx := context.Background()
	report, err := runner.Run(ctx)
	if err != nil {
		log.Fatalf("candidate discovery failed: %v", err)
	}

	if err := saveReport(*output, report); err != nil {
		log.Fatalf("failed to save report: %v", err)
	}

	fmt.Printf("Generated %d candidates\n", len(report.Candidates))
	fmt.Printf("Saved report to %s\n", *output)
	printTopResults(report, 12)
}

func loadConfig(configFile string) *config.Config {
	if strings.TrimSpace(configFile) == "" {
		return config.DefaultConfig()
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		log.Printf("warning: failed to load config %s: %v; using defaults", configFile, err)
		return config.DefaultConfig()
	}
	return cfg
}

func inferAssetsDir(strategyFile string) string {
	strategyFile = strings.TrimSpace(strategyFile)
	if strategyFile == "" {
		return filepath.Join("configs", "strategies")
	}
	return filepath.Dir(strategyFile)
}

func parseList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func saveReport(filename string, report *strategy.CandidateDiscoveryReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func printTopResults(report *strategy.CandidateDiscoveryReport, limit int) {
	fmt.Println()
	fmt.Printf("%-7s %-36s %-18s %-8s %-8s %-12s %-12s\n", "ID", "Candidate", "Domain", "Proto", "App%", "HS RTT", "APP RTT")
	fmt.Println(strings.Repeat("-", 116))

	for i, res := range report.Results {
		if i >= limit {
			break
		}
		fmt.Printf("%-7d %-36s %-18s %-8s %-7.1f%% %-12v %-12v\n",
			res.StrategyID,
			trim(res.StrategyName, 36),
			trim(res.Domain, 18),
			res.Protocol,
			res.AppSuccessRate*100,
			res.AvgHandshakeRTT,
			res.AvgAppRTT,
		)
	}
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
