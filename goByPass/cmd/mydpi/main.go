package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mydpi/internal/cache"
	"mydpi/internal/conntrack"
	"mydpi/internal/core"
	"mydpi/internal/strategy"
)

func main() {
	// Парсинг аргументов командной строки
	var (
		configFile = flag.String("config", "", "config file path")
		queueNum   = flag.Int("queue", 0, "NFQUEUE number")
		workers    = flag.Int("workers", 4, "number of worker goroutines")
		cacheSize  = flag.Int("cache-size", 10000, "IP cache size")
		cacheTTL   = flag.Duration("cache-ttl", 3600, "IP cache TTL")
	)
	flag.Parse()

	// Загрузка конфигурации
	var config map[string]interface{}
	if *configFile != "" {
		// Загружаем из файла
		data, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatal(err)
		}
		// парсим JSON/YAML...
	}

	// Инициализация компонентов
	ipCache := cache.NewIPCache(*cacheTTL, *cacheSize)
	connManager := conntrack.NewManager(5*time.Minute, 100000)
	strategyManager := strategy.NewManager()

	// Создание и запуск ядра
	dpiCore := core.NewCore(ipCache, connManager, strategyManager)

	if err := dpiCore.Start("linux", config); err != nil {
		log.Fatal(err)
	}

	log.Println("DPI bypass started successfully")

	// Ожидание сигнала завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	dpiCore.Stop()
}
