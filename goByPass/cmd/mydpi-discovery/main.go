package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"ByPass/internal/config"
	"ByPass/internal/strategy"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
	commit    = "unknown"
)

func main() {
	var (
		configFile  = flag.String("config", "", "path to config file (optional)")
		domains     = flag.String("domains", "", "comma-separated domains to test")
		ports       = flag.String("ports", "443", "comma-separated ports to test")
		outputFile  = flag.String("output", "discovery.json", "output file")
		samples     = flag.Int("samples", 10, "samples per test")
		timeout     = flag.Duration("timeout", 5*time.Second, "test timeout")
		showVersion = flag.Bool("version", false, "show version information")
	)
	flag.Parse()

	// Показываем версию
	if *showVersion {
		fmt.Printf("ByPass Discovery version %s\n", version)
		fmt.Printf("  build time: %s\n", buildTime)
		fmt.Printf("  commit: %s\n", commit)
		return
	}

	// Загружаем конфигурацию (опционально)
	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.Load(*configFile)
		if err != nil {
			log.Printf("Warning: failed to load config from %s: %v, using defaults", *configFile, err)
			cfg = config.DefaultConfig()
		}
	} else {
		cfg = config.DefaultConfig()
		log.Println("No config file specified, using default configuration")
	}

	// Создаем менеджер стратегий
	sm := strategy.NewManager()
	defer sm.Stop()

	// Загружаем стратегии из файла, если указан в конфиге
	if cfg.Strategy.StrategyFile != "" {
		if err := sm.LoadFromFile(cfg.Strategy.StrategyFile); err != nil {
			log.Printf("Warning: failed to load strategies from %s: %v",
				cfg.Strategy.StrategyFile, err)
		}
	}

	// Настраиваем тестовые домены
	testDomains := parseList(*domains)
	if len(testDomains) == 0 {
		// Используем домены из конфига или значения по умолчанию
		if len(cfg.Strategy.AutoDiscovery.TestDomains) > 0 {
			testDomains = cfg.Strategy.AutoDiscovery.TestDomains
		} else {
			testDomains = []string{
				"google.com",
				"youtube.com",
				"discord.com",
				"github.com",
				"telegram.org",
			}
		}
	}

	// Настраиваем тестовые порты
	testPorts := parseIntList(*ports)
	if len(testPorts) == 0 {
		// Используем порты из конфига или значения по умолчанию
		if len(cfg.Strategy.AutoDiscovery.TestPorts) > 0 {
			testPorts = cfg.Strategy.AutoDiscovery.TestPorts
		} else {
			testPorts = []int{443}
		}
	}

	// Создаем дискавери
	discovery := strategy.NewDiscovery(sm, strategy.DiscoveryConfig{
		TestDomains:    testDomains,
		TestPorts:      testPorts,
		TestTimeout:    *timeout,
		TestInterval:   100 * time.Millisecond,
		SamplesPerTest: *samples,
		MinSuccessRate: cfg.Strategy.AutoDiscovery.MinSuccessRate,
	})

	// Запускаем
	fmt.Printf("Starting discovery with %d domains, %d ports, %d samples\n",
		len(testDomains), len(testPorts), *samples)
	fmt.Printf("Testing %d strategies...\n", len(sm.ListStrategies()))
	fmt.Printf("Min success rate: %.1f%%\n", cfg.Strategy.AutoDiscovery.MinSuccessRate*100)

	start := time.Now()
	if err := discovery.Start(); err != nil {
		log.Fatal(err)
	}

	// Ждем завершения (в реальном коде нужно дождаться окончания)
	// Для простоты подождем расчетное время
	estimatedTime := time.Duration(len(testDomains)*len(testPorts)*len(sm.ListStrategies())*(*samples)) * 100 * time.Millisecond
	fmt.Printf("Estimated time: %v\n", estimatedTime)

	// Здесь нужно добавить ожидание завершения
	// В реальном коде discovery должен сигнализировать о завершении
	time.Sleep(estimatedTime + 5*time.Second)

	discovery.Stop()
	duration := time.Since(start)

	// Получаем результаты
	results := discovery.GetResults()

	// Выводим результаты
	fmt.Printf("\nDiscovery completed in %v\n", duration)
	fmt.Printf("Results:\n")
	fmt.Printf("%-4s %-20s %-12s %-15s %s\n", "ID", "Strategy", "Success Rate", "Avg Response", "Errors")
	fmt.Println("--------------------------------------------------------------------------------")

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

		fmt.Printf("%-4d %-20s %-11.1f%% %-15v %s\n",
			r.StrategyID,
			name,
			r.SuccessRate*100,
			r.AvgResponse,
			errMsg)
	}

	// Сохраняем в файл
	if err := saveResults(*outputFile, results); err != nil {
		log.Printf("Failed to save results: %v", err)
	} else {
		fmt.Printf("\nResults saved to %s\n", *outputFile)
	}

	// Выбираем лучшую стратегию
	best := discovery.GetBestStrategy()
	if best != nil {
		fmt.Printf("\n🎯 Best strategy: ID=%d with success rate %.1f%%\n",
			best.StrategyID, best.SuccessRate*100)

		// Показываем детали лучшей стратегии
		if strat, exists := sm.GetStrategy(best.StrategyID); exists {
			fmt.Printf("   Name: %s\n", strat.Name)
			fmt.Printf("   Description: %s\n", strat.Description)
			fmt.Printf("   Split mode: %v\n", strat.SplitMode)
			fmt.Printf("   Split positions: %v\n", strat.SplitPositions)
		}

		// Применяем (опционально)
		fmt.Print("\nApply this strategy as active? (y/n): ")
		var response string
		fmt.Scanln(&response)
		if response == "y" || response == "Y" {
			if err := sm.SetActive(best.StrategyID); err != nil {
				log.Printf("Failed to set active strategy: %v", err)
			} else {
				fmt.Println("✅ Strategy activated successfully")

				// Сохраняем обновленную стратегию в файл
				if cfg.Strategy.StrategyFile != "" {
					err := sm.SaveToFile(cfg.Strategy.StrategyFile)
					if err != nil {
						log.Printf("Failed to save strategies: %v", err)
					} else {
						fmt.Printf("Strategies saved to %s\n", cfg.Strategy.StrategyFile)
					}
				}
			}
		}
	} else {
		fmt.Println("\n❌ No strategy meets the minimum success rate")
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
