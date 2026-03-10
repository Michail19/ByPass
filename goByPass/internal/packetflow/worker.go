package packetflow

import (
	"sync"
	"time"

	"ByPass/internal/capture"
)

// WorkerPool пул воркеров для обработки пакетов
type WorkerPool struct {
	workers []*Worker
	tasks   chan capture.Packet
	results chan WorkerResult
	wg      sync.WaitGroup
	stats   WorkerPoolStats
}

// Worker отдельный воркер
type Worker struct {
	ID      int
	tasks   <-chan capture.Packet
	results chan<- WorkerResult
	process func(*capture.Packet) WorkerResult
	stats   WorkerStats
	mu      sync.Mutex
}

// WorkerResult результат обработки воркером
type WorkerResult struct {
	WorkerID    int
	PacketID    uint32
	ProcessTime time.Duration
	Modified    bool
	Error       error
}

// WorkerStats статистика воркера
type WorkerStats struct {
	PacketsProcessed uint64
	PacketsModified  uint64
	TotalTime        time.Duration
	AvgTime          time.Duration
	Errors           uint64
}

// WorkerPoolStats статистика пула
type WorkerPoolStats struct {
	ActiveWorkers  int
	TotalProcessed uint64
	TotalModified  uint64
	QueueLength    int
	AvgProcessTime time.Duration
	Throughput     float64 // пакетов в секунду
}

// NewWorkerPool создает новый пул воркеров
func NewWorkerPool(numWorkers int, queueSize int, processor func(*capture.Packet) WorkerResult) *WorkerPool {
	pool := &WorkerPool{
		workers: make([]*Worker, numWorkers),
		tasks:   make(chan capture.Packet, queueSize),
		results: make(chan WorkerResult, queueSize),
	}

	// Создаем воркеров
	for i := 0; i < numWorkers; i++ {
		worker := &Worker{
			ID:      i,
			tasks:   pool.tasks,
			results: pool.results,
			process: processor,
		}
		pool.workers[i] = worker
	}

	return pool
}

// Start запускает пул воркеров
func (p *WorkerPool) Start() {
	for _, worker := range p.workers {
		p.wg.Add(1)
		go worker.run()
	}

	// Запускаем сбор статистики
	go p.collectStats()
}

// Stop останавливает пул
func (p *WorkerPool) Stop() {
	close(p.tasks)
	p.wg.Wait()
	close(p.results)
}

// Submit отправляет пакет в очередь воркеров
// TODO: implement per-flow channel affinity for strict ordering within a TCP flow
func (p *WorkerPool) Submit(packet capture.Packet) bool {
	select {
	case p.tasks <- packet:
		return true
	default:
		return false
	}
}

// Results возвращает канал с результатами
func (p *WorkerPool) Results() <-chan WorkerResult {
	return p.results
}

// run основной цикл воркера
func (w *Worker) run() {
	for packet := range w.tasks {
		start := time.Now()
		result := w.process(&packet)
		result.WorkerID = w.ID
		result.PacketID = packet.ID
		result.ProcessTime = time.Since(start)

		w.mu.Lock()
		w.stats.PacketsProcessed++
		if result.Modified {
			w.stats.PacketsModified++
		}
		if result.Error != nil {
			w.stats.Errors++
		}
		w.stats.TotalTime += result.ProcessTime
		w.stats.AvgTime = w.stats.TotalTime / time.Duration(w.stats.PacketsProcessed)
		w.mu.Unlock()

		w.results <- result
	}
}

// GetStats возвращает статистику воркера
func (w *Worker) GetStats() WorkerStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}

// collectStats собирает статистику пула
func (p *WorkerPool) collectStats() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastProcessed uint64

	for range ticker.C {
		var totalProcessed, totalModified, totalErrors uint64
		var totalTime time.Duration

		for _, worker := range p.workers {
			stats := worker.GetStats()
			totalProcessed += stats.PacketsProcessed
			totalModified += stats.PacketsModified
			totalErrors += stats.Errors
			totalTime += stats.TotalTime
		}

		throughput := float64(totalProcessed-lastProcessed) / 1.0
		lastProcessed = totalProcessed

		var avgTime time.Duration
		if totalProcessed > 0 {
			avgTime = totalTime / time.Duration(totalProcessed)
		}

		p.stats = WorkerPoolStats{
			ActiveWorkers:  len(p.workers),
			TotalProcessed: totalProcessed,
			TotalModified:  totalModified,
			QueueLength:    len(p.tasks),
			AvgProcessTime: avgTime,
			Throughput:     throughput,
		}
	}
}

// GetStats возвращает статистику пула
func (p *WorkerPool) GetStats() WorkerPoolStats {
	return p.stats
}

// BalancedWorkerPool пул с балансировкой нагрузки
type BalancedWorkerPool struct {
	*WorkerPool
	// Можно добавить дополнительные функции для динамического масштабирования
}

// NewBalancedWorkerPool создает пул с автонастройкой
func NewBalancedWorkerPool(minWorkers, maxWorkers int, queueSize int, processor func(*capture.Packet) WorkerResult) *BalancedWorkerPool {
	pool := NewWorkerPool(minWorkers, queueSize, processor)

	// Запускаем мониторинг для динамического масштабирования
	go pool.monitorAndScale(minWorkers, maxWorkers)
	return &BalancedWorkerPool{WorkerPool: pool}
}

// monitorAndScale динамически меняет количество воркеров
func (p *WorkerPool) monitorAndScale(min, max int) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := p.GetStats()

		// Если очередь растет, добавляем воркеров
		if stats.QueueLength > cap(p.tasks)/2 && len(p.workers) < max {
			p.addWorker()
		}

		// Если очередь пуста и воркеров больше минимума, убираем
		if stats.QueueLength == 0 && len(p.workers) > min {
			p.removeWorker()
		}
	}
}

// addWorker добавляет нового воркера
func (p *WorkerPool) addWorker() {
	// В реальном коде нужно реализовать добавление
}

// removeWorker удаляет воркера
func (p *WorkerPool) removeWorker() {
	// В реальном коде нужно реализовать удаление
}
