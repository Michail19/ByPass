package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	_ "net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	_ "time"

	"ByPass/internal/config"
	"ByPass/internal/core"
)

func main() {
	var (
		configPath = flag.String("config", "/etc/mydpi/config.yaml", "config file")
		httpAddr   = flag.String("http", ":8080", "HTTP API address")
		daemonize  = flag.Bool("daemon", false, "run as daemon")
	)
	flag.Parse()

	// Демонизация
	if *daemonize {
		if err := daemonizeProcess(); err != nil {
			log.Fatal(err)
		}
	}

	// Загружаем конфигурацию
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	// Создаем PID файл
	if cfg.App.PidFile != "" {
		if err := createPidFile(cfg.App.PidFile); err != nil {
			log.Fatal(err)
		}
		defer os.Remove(cfg.App.PidFile)
	}

	// Запускаем ядро
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := core.StartDaemon(ctx, cfg); err != nil {
		log.Fatal(err)
	}

	// Запускаем HTTP API
	go startHTTPServer(*httpAddr)

	// Ожидаем сигнала
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	core.StopDaemon()
}

func daemonizeProcess() error {
	// Реализация демонизации для Unix-систем
	return nil
}

func createPidFile(path string) error {
	pid := os.Getpid()
	return os.WriteFile(path, []byte(fmt.Sprintf("%d", pid)), 0644)
}

func startHTTPServer(addr string) {
	// Метрики
	http.HandleFunc("/stats", statsHandler)
	http.HandleFunc("/flows", flowsHandler)
	http.HandleFunc("/strategies", strategiesHandler)
	http.HandleFunc("/reload", reloadHandler)

	log.Printf("HTTP API listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("HTTP server error: %v", err)
	}
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	stats := core.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func flowsHandler(w http.ResponseWriter, r *http.Request) {
	flows := core.GetFlows()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(flows)
}

func strategiesHandler(w http.ResponseWriter, r *http.Request) {
	strategies := core.GetStrategies()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(strategies)
}

func reloadHandler(w http.ResponseWriter, r *http.Request) {
	if err := core.ReloadConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
