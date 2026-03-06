package packetflow

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"ByPass/internal/cache"
	"ByPass/internal/capture"
	"ByPass/internal/conntrack"
	"ByPass/internal/modifier"
	"ByPass/internal/protocol"
	"ByPass/internal/sender"
	"ByPass/internal/strategy"
)

// Pipeline связывает все компоненты в конвейер обработки
type Pipeline struct {
	capturer    capture.Capturer
	conntrack   *conntrack.Manager
	pktModifier *modifier.PacketModifier
	sender      sender.Sender
	analyzer    *protocol.Analyzer
	ipCache     *cache.IPCache
	domainCache *cache.DomainCache
	strategyMgr *strategy.Manager

	workers    int
	packetChan chan capture.Packet
	resultChan chan modifier.ModifyResult
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc

	stats   PipelineStats
	statsMu sync.RWMutex
}

// PipelineStats статистика конвейера
type PipelineStats struct {
	PacketsReceived  uint64
	PacketsProcessed uint64
	PacketsModified  uint64
	PacketsSent      uint64
	PacketsDropped   uint64
	FlowsTracked     int
	CacheHits        uint64
	CacheMisses      uint64
	AvgProcessTime   time.Duration
	StartTime        time.Time
	LastPacketTime   time.Time
}

// Config конфигурация конвейера
type Config struct {
	Workers         int
	PacketQueueSize int
	ResultQueueSize int
	ProcessTimeout  time.Duration
}

// NewPipeline создает новый конвейер
func NewPipeline(
	capturer capture.Capturer,
	conntrack *conntrack.Manager,
	pktModifier *modifier.PacketModifier,
	sender sender.Sender,
	analyzer *protocol.Analyzer,
	ipCache *cache.IPCache,
	domainCache *cache.DomainCache,
	strategyMgr *strategy.Manager,
	cfg Config,
) *Pipeline {

	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.PacketQueueSize <= 0 {
		cfg.PacketQueueSize = 10000
	}
	if cfg.ResultQueueSize <= 0 {
		cfg.ResultQueueSize = 1000
	}

	return &Pipeline{
		capturer:    capturer,
		conntrack:   conntrack,
		pktModifier: pktModifier,
		sender:      sender,
		analyzer:    analyzer,
		ipCache:     ipCache,
		domainCache: domainCache,
		strategyMgr: strategyMgr,
		workers:     cfg.Workers,
		packetChan:  make(chan capture.Packet, cfg.PacketQueueSize),
		resultChan:  make(chan modifier.ModifyResult, cfg.ResultQueueSize),
		stats: PipelineStats{
			StartTime: time.Now(),
		},
	}
}

// Start запускает конвейер
func (p *Pipeline) Start() error {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Запускаем захват пакетов
	if err := p.capturer.Start(p.ctx); err != nil {
		return fmt.Errorf("failed to start capturer: %v", err)
	}

	// Запускаем воркеров
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}

	// Запускаем обработчик результатов
	p.wg.Add(1)
	go p.resultProcessor()

	// Передаем пакеты из капчера в канал
	go p.packetForwarder()

	log.Printf("Pipeline started with %d workers", p.workers)

	return nil
}

// Stop останавливает конвейер
func (p *Pipeline) Stop() {
	p.cancel()
	p.wg.Wait()

	if err := p.capturer.Stop(); err != nil {
		log.Printf("Error stopping capturer: %v", err)
	}

	if err := p.sender.Close(); err != nil {
		log.Printf("Error closing sender: %v", err)
	}

	close(p.packetChan)
	close(p.resultChan)
}

// packetForwarder передает пакеты из капчера в канал
func (p *Pipeline) packetForwarder() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case packet := <-p.capturer.Packets():
			p.updateStats(func(stats *PipelineStats) {
				stats.PacketsReceived++
				stats.LastPacketTime = time.Now()
			})

			// Неблокирующая отправка с таймаутом
			select {
			case p.packetChan <- packet:
			case <-time.After(100 * time.Millisecond):
				log.Printf("WARNING: Timeout sending to packet channel, dropping packet")
				p.updateStats(func(stats *PipelineStats) {
					stats.PacketsDropped++
				})
			}
		}
	}
}

// worker обрабатывает пакеты
func (p *Pipeline) worker(id int) {
	defer p.wg.Done()

	log.Printf("Worker %d started", id)

	for {
		select {
		case <-p.ctx.Done():
			return
		case packet := <-p.packetChan:
			p.processPacket(&packet)
		}
	}
}

// processPacket временная версия для тестирования
func (p *Pipeline) processPacket(pkt *capture.Packet) {
	startTime := time.Now()

	if len(pkt.Data) < 20 {
		log.Printf("WARNING: Packet too short (%d bytes) from %v, hex: % x",
			len(pkt.Data), pkt.Interface, pkt.Data[:len(pkt.Data)])
		// Все равно пытаемся отправить, может быть это валидный пакет
	}

	// Сохраняем адрес из пакета
	addr := pkt.Addr

	// Используем специальный метод отправки с адресом
	if rs, ok := p.sender.(*sender.RawSender); ok && len(addr) == 64 {
		// Это WinDivert sender - используем SendWithAddr
		if err := rs.SendWithAddr(pkt.Data, addr); err != nil {
			log.Printf("ERROR: Failed to send packet via WinDivert: %v", err)
		}
	} else {
		// Обычный sender (raw socket)
		if err := p.sender.Send(pkt.Data); err != nil {
			log.Printf("ERROR: Failed to send packet: %v", err)
		}
	}

	p.updateStats(func(stats *PipelineStats) {
		stats.PacketsReceived++
		stats.PacketsSent++
		stats.PacketsProcessed++
	})

	processTime := time.Since(startTime)
	p.updateStats(func(stats *PipelineStats) {
		stats.AvgProcessTime = (stats.AvgProcessTime + processTime) / 2
	})
}

// processPacket обрабатывает один пакет
//func (p *Pipeline) processPacket(pkt *capture.Packet) {
//	startTime := time.Now()
//
//	// Проверяем минимальную длину пакета
//	if len(pkt.Data) < 20 {
//		log.Printf("WARNING: Packet too short (%d bytes), forwarding original", len(pkt.Data))
//		p.sender.Send(pkt.Data)
//		return
//	}
//
//	// Извлекаем IP и порты
//	srcIP, dstIP, err := p.extractIPs(pkt.Data)
//	if err != nil {
//		return
//	}
//
//	srcPort, dstPort, err := p.extractPorts(pkt.Data)
//	if err != nil {
//		return
//	}
//
//	// Получаем или создаем поток
//	flow := p.conntrack.GetOrCreate(srcIP, dstIP, srcPort, dstPort, p.getProtocol(pkt.Data))
//
//	// Анализируем пакет
//	info, err := p.analyzer.Analyze(pkt.Data, srcIP.String(), dstIP.String(), srcPort, dstPort)
//	if err == nil && info != nil {
//		// Сохраняем информацию в поток
//		if info.SNI != "" {
//			flow.SetHostname(info.SNI)
//		} else if info.Host != "" {
//			flow.SetHostname(info.Host)
//		}
//		if info.IsTLS {
//			flow.SetTLS()
//		}
//		if info.IsHTTP {
//			flow.SetHTTP()
//		}
//	}
//
//	// Проверяем кэш
//	var shouldBypass bool
//	var strategyID int
//
//	if cached, exists := p.ipCache.GetByIP(dstIP); exists {
//		shouldBypass = cached.ShouldBypass
//		strategyID = cached.StrategyID
//		p.updateStats(func(stats *PipelineStats) {
//			stats.CacheHits++
//		})
//		log.Printf("DEBUG: Cache hit for %s: bypass=%v strategy=%d",
//			dstIP.String(), shouldBypass, strategyID)
//	} else {
//		// Решаем, нужно ли обходить
//		strat := p.strategyMgr.SelectStrategy(
//			dstIP.String(),
//			flow.Hostname,
//			int(dstPort),
//			"tcp",
//		)
//		if strat != nil {
//			shouldBypass = true
//			strategyID = strat.ID
//			log.Printf("DEBUG: Selected strategy %d (%s) for %s (hostname: %s)",
//				strategyID, strat.Name, dstIP.String(), flow.Hostname)
//		} else {
//			log.Printf("DEBUG: No strategy for %s", dstIP.String())
//		}
//		p.ipCache.PutByIP(dstIP, flow.Hostname, shouldBypass, strategyID)
//		p.updateStats(func(stats *PipelineStats) {
//			stats.CacheMisses++
//		})
//	}
//
//	// Применяем модификацию если нужно
//	if shouldBypass {
//		result, err := p.pktModifier.ModifyPacket(pkt.Data, flow)
//		if err == nil && result != nil {
//			validPackets := 0
//			for i, modifiedPkt := range result.ModifiedPackets {
//				// Проверяем целостность модифицированного пакета
//				if len(modifiedPkt) < 20 {
//					log.Printf("WARNING: Modified packet %d too short (%d bytes), skipping",
//						i, len(modifiedPkt))
//					continue
//				}
//
//				// Проверяем, что это похоже на IP-пакет
//				if modifiedPkt[0]>>4 != 4 {
//					log.Printf("WARNING: Modified packet %d not IPv4 (version=%d)",
//						i, modifiedPkt[0]>>4)
//				}
//
//				if err := p.sender.Send(modifiedPkt); err == nil {
//					validPackets++
//					p.updateStats(func(stats *PipelineStats) {
//						stats.PacketsModified++
//						stats.PacketsSent++
//					})
//				} else {
//					log.Printf("ERROR: Failed to send modified packet %d: %v", i, err)
//				}
//			}
//
//			log.Printf("DEBUG: Sent %d/%d modified packets for flow to %s",
//				validPackets, len(result.ModifiedPackets), dstIP.String())
//
//			// Если нужно, отправляем оригинал
//			if result.SendOriginal && len(pkt.Data) >= 20 {
//				if err := p.sender.Send(pkt.Data); err == nil {
//					p.updateStats(func(stats *PipelineStats) {
//						stats.PacketsSent++
//					})
//				}
//			}
//		}
//	} else {
//		// Просто отправляем оригинал
//		if err := p.sender.Send(pkt.Data); err == nil {
//			p.updateStats(func(stats *PipelineStats) {
//				stats.PacketsSent++
//			})
//		}
//	}
//
//	// Обновляем статистику обработки
//	processTime := time.Since(startTime)
//	p.updateStats(func(stats *PipelineStats) {
//		stats.PacketsProcessed++
//		stats.AvgProcessTime = (stats.AvgProcessTime + processTime) / 2
//	})
//}

// resultProcessor обрабатывает результаты модификации
func (p *Pipeline) resultProcessor() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case result := <-p.resultChan:
			// Отправляем результат в менеджер стратегий для статистики
			if p.strategyMgr != nil {
				// Создаем StrategyResult из ModifyResult
				strategyResult := &strategy.StrategyResult{
					StrategyID:   0, // Здесь нужно получить ID стратегии
					Success:      true,
					ResponseTime: 0,
					BytesSent:    0,
					PacketsSent:  len(result.ModifiedPackets),
					Timestamp:    time.Now(),
				}
				p.strategyMgr.ReportResult(strategyResult)
			}
		}
	}
}

// extractIPs извлекает IP-адреса из пакета
func (p *Pipeline) extractIPs(packet []byte) (srcIP, dstIP net.IP, err error) {
	if len(packet) < 20 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	version := packet[0] >> 4
	if version == 4 {
		return net.IP(packet[12:16]), net.IP(packet[16:20]), nil
	}

	return nil, nil, fmt.Errorf("unsupported IP version")
}

// extractPorts извлекает порты из пакета
func (p *Pipeline) extractPorts(packet []byte) (srcPort, dstPort uint16, err error) {
	if len(packet) < 20 {
		return 0, 0, fmt.Errorf("packet too short")
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	if len(packet) < int(ipHeaderLen)+4 {
		return 0, 0, fmt.Errorf("packet too short for TCP header")
	}

	tcpOffset := int(ipHeaderLen)
	srcPort = uint16(packet[tcpOffset])<<8 | uint16(packet[tcpOffset+1])
	dstPort = uint16(packet[tcpOffset+2])<<8 | uint16(packet[tcpOffset+3])

	return srcPort, dstPort, nil
}

// getProtocol возвращает протокол пакета
func (p *Pipeline) getProtocol(packet []byte) uint8 {
	if len(packet) < 9 {
		return 0
	}
	return packet[9] // protocol field in IPv4 header
}

// updateStats обновляет статистику
func (p *Pipeline) updateStats(updater func(*PipelineStats)) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	updater(&p.stats)
}

// GetStats возвращает статистику
func (p *Pipeline) GetStats() PipelineStats {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()
	return p.stats
}
