package packetflow

import (
	"context"
	"encoding/binary"
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

// packetForwarder с буферизацией и контролем переполнения
func (p *Pipeline) packetForwarder() {
	// Создаем временный буфер для пакетов, которые не влезли в канал
	tempBuffer := make([]capture.Packet, 0, 100)

	for {
		select {
		case <-p.ctx.Done():
			// Отправляем все из временного буфера перед выходом
			for _, packet := range tempBuffer {
				p.processPacket(&packet)
			}
			return

		case packet := <-p.capturer.Packets():
			p.updateStats(func(stats *PipelineStats) {
				stats.PacketsReceived++
				stats.LastPacketTime = time.Now()
			})

			// Сначала отправляем все из временного буфера
			for len(tempBuffer) > 0 {
				select {
				case p.packetChan <- tempBuffer[0]:
					tempBuffer = tempBuffer[1:]
				default:
					// Канал все еще переполнен, выходим
					break
				}
			}

			// Пытаемся отправить новый пакет
			select {
			case p.packetChan <- packet:
				// Успешно
			default:
				// Канал переполнен, сохраняем во временный буфер
				if len(tempBuffer) < cap(tempBuffer) {
					tempBuffer = append(tempBuffer, packet)
					log.Printf("WARNING: Packet channel full, buffering (%d/%d)",
						len(tempBuffer), cap(tempBuffer))
				} else {
					// Буфер тоже переполнен - дропаем
					p.updateStats(func(stats *PipelineStats) {
						stats.PacketsDropped++
					})
					log.Printf("ERROR: Buffer full, dropping packet")
				}
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

// processPacket обрабатывает один пакет (полная версия)
func (p *Pipeline) processPacket(pkt *capture.Packet) {
	startTime := time.Now()

	// Проверяем минимальную длину пакета
	if len(pkt.Data) < 20 {
		log.Printf("WARNING: Packet too short (%d bytes), forwarding original", len(pkt.Data))
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	// Извлекаем IP и порты
	srcIP, dstIP, err := p.extractIPs(pkt.Data)
	if err != nil {
		log.Printf("WARNING: Failed to extract IPs: %v", err)
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	// В processPacket, замените вызов extractPorts:
	srcPort, dstPort, protocol, err := p.extractPorts(pkt.Data)
	if err != nil {
		log.Printf("WARNING: Failed to extract ports: %v", err)
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	// При создании потока используйте правильный протокол
	flow := p.conntrack.GetOrCreate(srcIP, dstIP, srcPort, dstPort, protocol)

	// Анализируем пакет
	info, err := p.analyzer.Analyze(pkt.Data, srcIP.String(), dstIP.String(), srcPort, dstPort)
	if err == nil && info != nil {
		// Сохраняем информацию в поток
		if info.SNI != "" {
			flow.SetHostname(info.SNI)
		} else if info.Host != "" {
			flow.SetHostname(info.Host)
		}
		if info.IsTLS {
			flow.SetTLS()
		}
		if info.IsHTTP {
			flow.SetHTTP()
		}
	}

	// Проверяем кэш
	var shouldBypass bool
	var strategyID int

	if cached, exists := p.ipCache.GetByIP(dstIP); exists {
		shouldBypass = cached.ShouldBypass
		strategyID = cached.StrategyID
		p.updateStats(func(stats *PipelineStats) {
			stats.CacheHits++
		})
		log.Printf("DEBUG: Cache hit for %s: bypass=%v strategy=%d",
			dstIP.String(), shouldBypass, strategyID)
	} else {
		// Решаем, нужно ли обходить
		strat := p.strategyMgr.SelectStrategy(
			dstIP.String(),
			flow.Hostname,
			int(dstPort),
			"tcp",
		)
		if strat != nil {
			shouldBypass = true
			strategyID = strat.ID
			log.Printf("DEBUG: Selected strategy %d (%s) for %s (hostname: %s)",
				strategyID, strat.Name, dstIP.String(), flow.Hostname)
		} else {
			log.Printf("DEBUG: No strategy for %s", dstIP.String())
		}
		p.ipCache.PutByIP(dstIP, flow.Hostname, shouldBypass, strategyID)
		p.updateStats(func(stats *PipelineStats) {
			stats.CacheMisses++
		})
	}

	// Применяем модификацию если нужно
	if shouldBypass {
		result, err := p.pktModifier.ModifyPacket(pkt.Data, flow)
		if err == nil && result != nil {
			validPackets := 0
			for i, modifiedPkt := range result.ModifiedPackets {
				// Проверяем целостность модифицированного пакета
				if len(modifiedPkt) < 20 {
					log.Printf("WARNING: Modified packet %d too short (%d bytes), skipping",
						i, len(modifiedPkt))
					continue
				}

				// Проверяем, что это похоже на IP-пакет
				if modifiedPkt[0]>>4 != 4 {
					log.Printf("WARNING: Modified packet %d not IPv4 (version=%d)",
						i, modifiedPkt[0]>>4)
				}

				if p.sendPacket(modifiedPkt, pkt.Addr) {
					validPackets++
					p.updateStats(func(stats *PipelineStats) {
						stats.PacketsModified++
						stats.PacketsSent++
					})
				}
			}

			log.Printf("DEBUG: Sent %d/%d modified packets for flow to %s",
				validPackets, len(result.ModifiedPackets), dstIP.String())

			// Если нужно, отправляем оригинал
			if result.SendOriginal && len(pkt.Data) >= 20 {
				if p.sendPacket(pkt.Data, pkt.Addr) {
					p.updateStats(func(stats *PipelineStats) {
						stats.PacketsSent++
					})
				}
			}
		}
	} else {
		// Просто отправляем оригинал
		if p.sendPacket(pkt.Data, pkt.Addr) {
			p.updateStats(func(stats *PipelineStats) {
				stats.PacketsSent++
			})
		}
	}

	// Обновляем статистику обработки
	processTime := time.Since(startTime)
	p.updateStats(func(stats *PipelineStats) {
		stats.PacketsProcessed++
		stats.AvgProcessTime = (stats.AvgProcessTime + processTime) / 2
	})
}

// sendPacket отправляет пакет с учетом типа sender
func (p *Pipeline) sendPacket(data []byte, addr []byte) bool {
	if len(data) < 20 {
		log.Printf("WARNING: Attempted to send packet too short (%d bytes)", len(data))
		return false
	}

	// Для WinDivert sender используем SendWithAddr
	if rs, ok := p.sender.(*sender.RawSender); ok {
		// Проверяем, что адрес не nil
		if addr == nil {
			log.Printf("WARNING: Nil address for WinDivert, creating dummy")
			addr = make([]byte, 64)
		}

		if err := rs.SendWithAddr(data, addr); err != nil {
			log.Printf("ERROR: Failed to send packet via WinDivert: %v", err)
			return false
		}
		return true
	}

	// Для обычного sender
	if err := p.sender.Send(data); err != nil {
		log.Printf("ERROR: Failed to send packet: %v", err)
		return false
	}
	return true
}

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
					StrategyID:   result.StrategyID, // Теперь StrategyID сохраняется!
					Success:      true,
					ResponseTime: time.Duration(result.Delay) * time.Millisecond,
					BytesSent:    len(result.ModifiedPackets) * 1500, // Примерно
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

// extractPorts извлекает source и destination порты только для TCP/UDP
func (p *Pipeline) extractPorts(packet []byte) (srcPort, dstPort uint16, protocol uint8, err error) {
	if len(packet) < 20 {
		return 0, 0, 0, fmt.Errorf("packet too short")
	}

	protocol = packet[9]

	// Только для TCP (6) и UDP (17)
	if protocol != 6 && protocol != 17 {
		return 0, 0, protocol, nil
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	if len(packet) < int(ipHeaderLen)+4 {
		return 0, 0, protocol, fmt.Errorf("packet too short for transport header")
	}

	transportOffset := int(ipHeaderLen)
	srcPort = binary.BigEndian.Uint16(packet[transportOffset:])
	dstPort = binary.BigEndian.Uint16(packet[transportOffset+2:])

	return srcPort, dstPort, protocol, nil
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
