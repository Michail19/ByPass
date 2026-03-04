package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"ByPass/internal/strategy"
)

func main() {
	var (
		configFile = flag.String("config", "config.yaml", "config file")
		domains    = flag.String("domains", "", "comma-separated domains to test")
		ports      = flag.String("ports", "443", "comma-separated ports to test")
		outputFile = flag.String("output", "discovery.json", "output file")
		samples    = flag.Int("samples", 10, "samples per test")
		timeout    = flag.Duration("timeout", 5*time.Second, "test timeout")
	)
	flag.Parse()

	// Загружаем конфигурацию
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Создаем менеджер стратегий
	sm := strategy.NewManager()
	defer sm.Stop()

	// Загружаем стратегии
	if err := sm.LoadFromFile(cfg.StrategyFile); err != nil {
		log.Printf("Warning: %v", err)
	}

	// Настраиваем тестовые домены
	testDomains := parseList(*domains)
	if len(testDomains) == 0 {
		testDomains = []string{
			"google.com",
			"youtube.com",
			"discord.com",
			"github.com",
		}
	}

	// Настраиваем тестовые порты
	testPorts := parseIntList(*ports)

	// Создаем дискавери
	discovery := strategy.NewDiscovery(sm, strategy.DiscoveryConfig{
		TestDomains:    testDomains,
		TestPorts:      testPorts,
		TestTimeout:    *timeout,
		TestInterval:   100 * time.Millisecond,
		SamplesPerTest: *samples,
		MinSuccessRate: 0.7,
	})

	// Запускаем
	fmt.Printf("Starting discovery with %d domains, %d ports, %d samples\n",
		len(testDomains), len(testPorts), *samples)
	fmt.Printf("Testing %d strategies...\n", len(sm.ListStrategies()))

	start := time.Now()
	if err := discovery.Start(); err != nil {
		log.Fatal(err)
	}

	// Ждем завершения
	discovery.Stop()
	duration := time.Since(start)

	// Получаем результаты
	results := discovery.GetResults()

	// Выводим результаты
	fmt.Printf("\nDiscovery completed in %v\n", duration)
	fmt.Printf("Results:\n")
	fmt.Printf("%-4s %-20s %-10s %-15s %s\n", "ID", "Strategy", "Success", "Avg Response", "Errors")
	fmt.Println("--------------------------------------------------------")

	for _, r := range results {
		strat, _ := sm.GetStrategy(r.StrategyID)
		name := "unknown"
		if strat != nil {
			name = strat.Name
		}

		errMsg := ""
		if len(r.Errors) > 0 {
			errMsg = fmt.Sprintf("%d errors", len(r.Errors))
		}

		fmt.Printf("%-4d %-20s %-10.1f%% %-15v %s\n",
			r.StrategyID,
			name,
			r.SuccessRate*100,
			r.AvgResponse,
			errMsg)
	}

	// Сохраняем в файл
	if err := saveResults(*outputFile, results); err != nil {
		log.Printf("Failed to save results: %v", err)
	}

	// Выбираем лучшую стратегию
	best := discovery.GetBestStrategy()
	if best != nil {
		fmt.Printf("\nBest strategy: ID=%d with success rate %.1f%%\n",
			best.StrategyID, best.SuccessRate*100)

		// Применяем
		if err := sm.SetActive(best.StrategyID); err != nil {
			log.Printf("Failed to set active strategy: %v", err)
		}
	}
}

func parseList(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parseIntList(s string) []int {
	if s == "" {
		return nil
	}
	var result []int
	for _, item := range strings.Split(s, ",") {
		var val int
		if _, err := fmt.Sscanf(item, "%d", &val); err == nil {
			result = append(result, val)
		}
	}
	return result
}

func saveResults(filename string, results []*strategy.DiscoveryResult) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}
