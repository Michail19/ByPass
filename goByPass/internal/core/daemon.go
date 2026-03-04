package core

import (
	"ByPass/pkg/models"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ByPass/internal/config"
)

var (
	globalCore *Core
	coreMu     sync.Mutex
)

// StartDaemon запускает ядро в режиме демона
func StartDaemon(ctx context.Context, cfg *config.Config) error {
	coreMu.Lock()
	defer coreMu.Unlock()

	if globalCore != nil {
		return fmt.Errorf("daemon already running")
	}

	// Создаем ядро
	globalCore = NewCore(cfg)

	// Инициализируем
	if err := globalCore.Init(); err != nil {
		return fmt.Errorf("failed to initialize core: %v", err)
	}

	// Запускаем
	if err := globalCore.Start(ctx); err != nil {
		globalCore.Stop()
		return fmt.Errorf("failed to start core: %v", err)
	}

	// Настраиваем обработку сигналов для graceful shutdown
	go handleSignals()

	log.Println("Daemon started successfully")
	return nil
}

// StopDaemon останавливает демон
func StopDaemon() {
	coreMu.Lock()
	defer coreMu.Unlock()

	if globalCore != nil {
		globalCore.Stop()
		globalCore = nil
	}
}

// GetStats возвращает статистику демона
func GetStats() CoreStats {
	coreMu.Lock()
	defer coreMu.Unlock()

	if globalCore == nil {
		return CoreStats{}
	}
	return globalCore.GetStats()
}

// GetFlows возвращает список потоков
func GetFlows() []*models.Flow {
	coreMu.Lock()
	defer coreMu.Unlock()

	if globalCore == nil {
		return nil
	}
	return globalCore.GetFlows()
}

// GetStrategies возвращает список стратегий
func GetStrategies() []*models.Strategy {
	coreMu.Lock()
	defer coreMu.Unlock()

	if globalCore == nil {
		return nil
	}
	return globalCore.GetStrategies()
}

// ReloadConfig перезагружает конфигурацию
func ReloadConfig() error {
	coreMu.Lock()
	defer coreMu.Unlock()

	if globalCore == nil {
		return fmt.Errorf("daemon not running")
	}
	return globalCore.ReloadConfig()
}

// handleSignals обрабатывает сигналы ОС
func handleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigChan {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("Received signal %v, shutting down...", sig)
			StopDaemon()
			os.Exit(0)

		case syscall.SIGHUP:
			log.Printf("Received SIGHUP, reloading config...")
			if err := ReloadConfig(); err != nil {
				log.Printf("Failed to reload config: %v", err)
			}
		}
	}
}

// HealthCheck проверяет здоровье демона
func HealthCheck() map[string]interface{} {
	coreMu.Lock()
	defer coreMu.Unlock()

	status := map[string]interface{}{
		"status": "ok",
		"time":   time.Now(),
	}

	if globalCore == nil {
		status["status"] = "stopped"
		return status
	}

	stats := globalCore.GetStats()
	status["uptime"] = stats.UptimeSeconds
	status["packets"] = map[string]uint64{
		"received":  stats.PacketsReceived,
		"processed": stats.PacketsProcessed,
		"modified":  stats.PacketsModified,
		"sent":      stats.PacketsSent,
		"dropped":   stats.PacketsDropped,
	}
	status["flows"] = stats.FlowsTracked
	status["cache"] = map[string]uint64{
		"hits":   stats.CacheHits,
		"misses": stats.CacheMisses,
	}

	return status
}
