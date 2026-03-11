package packetflow

import (
	"sync"
	"time"
)

// WorkerStats статистика одного воркера.
// Используется pipeline для агрегированной статистики через GetStats().
type WorkerStats struct {
	PacketsProcessed uint64
	PacketsModified  uint64
	TotalTime        time.Duration
	AvgTime          time.Duration
	Errors           uint64
}

// workerStatsCollector агрегирует статистику всех воркеров пайплайна.
// Запускается как горутина в Pipeline.Start().
type workerStatsCollector struct {
	mu         sync.Mutex
	statsByID  map[int]*WorkerStats
	throughput float64 // пакетов/сек, обновляется каждую секунду
}

func newWorkerStatsCollector(numWorkers int) *workerStatsCollector {
	c := &workerStatsCollector{
		statsByID: make(map[int]*WorkerStats, numWorkers),
	}
	for i := 0; i < numWorkers; i++ {
		c.statsByID[i] = &WorkerStats{}
	}
	return c
}

// Record фиксирует результат обработки пакета воркером.
func (c *workerStatsCollector) Record(workerID int, modified bool, elapsed time.Duration, hasErr bool) {
	c.mu.Lock()
	s, ok := c.statsByID[workerID]
	if !ok {
		s = &WorkerStats{}
		c.statsByID[workerID] = s
	}
	s.PacketsProcessed++
	if modified {
		s.PacketsModified++
	}
	if hasErr {
		s.Errors++
	}
	s.TotalTime += elapsed
	s.AvgTime = s.TotalTime / time.Duration(s.PacketsProcessed)
	c.mu.Unlock()
}

// Snapshot возвращает суммарную статистику по всем воркерам.
func (c *workerStatsCollector) Snapshot() WorkerStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	var agg WorkerStats
	for _, s := range c.statsByID {
		agg.PacketsProcessed += s.PacketsProcessed
		agg.PacketsModified += s.PacketsModified
		agg.Errors += s.Errors
		agg.TotalTime += s.TotalTime
	}
	if agg.PacketsProcessed > 0 {
		agg.AvgTime = agg.TotalTime / time.Duration(agg.PacketsProcessed)
	}
	return agg
}
