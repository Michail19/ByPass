package packetflow

import (
	"context"
	"crypto/rand"
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
	workers     int
	packetChan  chan capture.Packet
	resultChan  chan modifier.ModifyResult
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	stats       PipelineStats
	statsMu     sync.RWMutex
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
	TotalProcessTime time.Duration
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

	// NOTE: capturer is already started by the caller (initializeComponents)
	// to obtain the WinDivert handle before building the sender.
	// Do NOT call p.capturer.Start() here to avoid opening a second handle.

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
			for len(tempBuffer) > 0 && len(p.packetChan) < cap(p.packetChan) {
				p.packetChan <- tempBuffer[0]
				tempBuffer = tempBuffer[1:]
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
		case packet, ok := <-p.packetChan:
			if !ok {
				return // channel closed
			}
			p.processPacket(&packet)
		}
	}
}

// processPacket обрабатывает один пакет
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

	srcPort, dstPort, protocol, err := p.extractPorts(pkt.Data)
	if err != nil {
		log.Printf("WARNING: Failed to extract ports: %v", err)
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	// Получаем или создаём поток
	flow := p.conntrack.GetOrCreate(srcIP, dstIP, srcPort, dstPort, protocol)
	if !flow.IsAnalyzed {
		info, err := p.analyzer.Analyze(pkt.Data, srcIP.String(), dstIP.String(), srcPort, dstPort)
		if err == nil && info != nil {
			if info.SNI != "" {
				flow.SetHostname(info.SNI)
				flow.IsAnalyzed = true // hostname found — lock it in
			} else if info.Host != "" {
				flow.SetHostname(info.Host)
				flow.IsAnalyzed = true
			}
			if info.IsTLS {
				flow.SetTLS()
			}
			if info.IsHTTP {
				flow.SetHTTP()
			}
		}
		// Give up analyzing after 4 packets with no result to avoid wasting CPU
		// on data packets that will never contain a ClientHello
		flow.Mu.Lock()
		flow.DataPacketsModified++ // reuse as analysis-attempt counter temporarily
		giveUp := flow.DataPacketsModified >= 4
		if giveUp {
			flow.IsAnalyzed = true
			flow.DataPacketsModified = 0 // reset for actual use below
		}
		flow.Mu.Unlock()
	}

	// Проверяем кэш
	var shouldBypass bool
	var strategyID int
	var strats *strategy.Strategy // ← всегда указатель, может быть nil
	cachedStratID := 0
	var cached *cache.IPCacheEntry // keep in scope for fallback below
	if c, exists := p.ipCache.GetByIP(dstIP); exists {
		cached = c
		cachedStratID = cached.StrategyID
		shouldBypass = cached.ShouldBypass
		strategyID = cached.StrategyID
		p.updateStats(func(stats *PipelineStats) { stats.CacheHits++ })
		log.Printf("[STRATEGY] Cache hit for %s:%d: bypass=%v, cached strategy=%d (hostname in cache: %s)",
			dstIP.String(), dstPort, shouldBypass, strategyID, cached.Hostname)
	}

	// Always trust the fresh strategy selection — hostname-based routing takes priority over cache
	strat := p.strategyMgr.SelectStrategy(
		dstIP.String(),
		flow.Hostname,
		int(dstPort),
		"tcp",
	)

	if strat != nil {
		log.Printf("[STRATEGY] Fresh select → strategy %d (%s) (hostname: %s)",
			strat.ID, strat.Name, flow.Hostname)

		strats = strat
		strategyID = strat.ID
		// Only bypass if strategy is not the passthrough (id=1)
		shouldBypass = strat.ID != 1

		// Update cache if strategy changed or wasn't set
		if strat.ID != cachedStratID {
			log.Printf("[STRATEGY] Updating to fresh strategy %d (was %d)", strat.ID, cachedStratID)
			p.ipCache.PutByIP(dstIP, flow.Hostname, shouldBypass, strategyID)
		}
	} else if cachedStratID != 0 && cachedStratID != 1 && cached != nil {
		// No fresh selection but we have a valid cached non-passthrough strategy
		strats, _ = p.strategyMgr.GetStrategy(cachedStratID)
		shouldBypass = cached.ShouldBypass
	}

	// 3. Финальный fallback, если ничего не выбрано
	if strats == nil {
		strategyID = 1
		strats, _ = p.strategyMgr.GetStrategy(1)
		if strats == nil {
			log.Printf("[STRATEGY] CRITICAL: No passthrough strategy (id=1) found!")
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}
		shouldBypass = false // passthrough = без модификаций
	}

	log.Printf("[STRATEGY] Final decision for %s:%d (hostname: %s): strategy %d (%s), bypass=%v",
		dstIP.String(), dstPort, flow.Hostname, strategyID, strats.Name, shouldBypass)

	if shouldBypass {
		// Определить тип пакета (уже есть)
		ipHeaderLen := int(pkt.Data[0]&0x0F) * 4
		tcpOffset := ipHeaderLen
		flags := pkt.Data[tcpOffset+13]
		isSYN := (flags & 0x02) != 0
		isACK := (flags & 0x10) != 0
		tcpHeaderLen := int(pkt.Data[tcpOffset+12]>>4) * 4
		payloadOffset := tcpOffset + tcpHeaderLen
		isData := len(pkt.Data) > payloadOffset
		isClientHello := isData &&
			len(pkt.Data) >= payloadOffset+6 && // need indices [+0..+5]
			pkt.Data[payloadOffset] == 0x16 && // ContentType: Handshake
			pkt.Data[payloadOffset+1] == 0x03 && // TLS major version
			pkt.Data[payloadOffset+5] == 0x01 // HandshakeType: ClientHello

		applyMods := (isClientHello && strats.ApplyToTLS && !flow.IsHandshakeModified) ||
			(isData && !isClientHello && flow.DataPacketsModified < strats.ModifyFirstDataPackets)
		if applyMods {
			flow.Mu.Lock()
			if isClientHello {
				flow.IsHandshakeModified = true
			}
			// Increment перенесён ниже, после успеха
			flow.Mu.Unlock()
		}

		// QUIC отдельно, но без TTL для всех — только если стратегия требует
		if protocol == 17 && dstPort == 443 {
			if strats.QUICttl > 0 {
				setIPTTL(pkt.Data, strats.QUICttl)
				recalculateIPChecksum(pkt.Data)
			}
			if strats != nil && strats.FakeQUIC {
				fakeQUIC := makeFakeQUICInitial(pkt.Data)
				if len(fakeQUIC) > 0 {
					p.sendPacket(fakeQUIC, pkt.Addr)
				}
			}

			p.sendPacket(pkt.Data, pkt.Addr)

			return
		}

		if !applyMods {
			// Пропускаем data-пакеты без модификаций
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}

		log.Printf("[STRATEGY] Applying modifications with strategy %d (%s) for %s (SYN=%v ACK=%v ClientHello=%v Data=%v)",
			strategyID, strats.Name, dstIP.String(), isSYN, isACK, isClientHello, isData)

		// Только здесь применяем модификации
		result, err := p.pktModifier.ModifyPacket(pkt.Data, flow)
		if err != nil {
			log.Printf("[STRATEGY] ModifyPacket error: %v, sending original", err)
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}

		if result == nil {
			log.Printf("[STRATEGY] ModifyPacket returned nil result for strategy %d", strategyID)
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}

		// Отправляем модифицированные
		if len(result.ModifiedPackets) > 0 {
			for i, modPkt := range result.ModifiedPackets {
				if len(modPkt) >= 20 && (modPkt[0]>>4 == 4) {
					// Добавлен recalc checksum после модификации
					fixTCPChecksum(modPkt)
					recalculateIPChecksum(modPkt)
					p.sendPacket(modPkt, pkt.Addr)
					p.updateStats(func(stats *PipelineStats) {
						stats.PacketsModified++
						stats.PacketsSent++
					})
				} else {
					log.Printf("WARNING: Invalid modified packet %d, skipping", i)
				}
			}
			// Increment только после успешной модификации
			flow.Mu.Lock()
			if !isClientHello {
				flow.DataPacketsModified++
			}
			flow.Mu.Unlock()
		}

		// Отправляем оригинал (если нужно)
		if result.SendOriginal {
			p.sendPacket(pkt.Data, pkt.Addr)
			p.updateStats(func(stats *PipelineStats) {
				stats.PacketsSent++
			})
		}
	} else {
		p.sendPacket(pkt.Data, pkt.Addr)
	}

	// Статистика
	processTime := time.Since(startTime)
	p.updateStats(func(stats *PipelineStats) {
		stats.PacketsProcessed++
		stats.TotalProcessTime += processTime
		if stats.PacketsProcessed > 0 {
			stats.AvgProcessTime = stats.TotalProcessTime / time.Duration(stats.PacketsProcessed)
		}
	})
}

// fixTCPChecksum пересчитывает TCP контрольную сумму
func fixTCPChecksum(packet []byte) {
	if len(packet) < 40 {
		return
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	tcpOffset := int(ipHeaderLen)

	if len(packet) < tcpOffset+20 {
		return
	}

	packet[tcpOffset+16] = 0
	packet[tcpOffset+17] = 0

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], packet[12:16]) // Source IP
	copy(pseudo[4:8], packet[16:20]) // Dest IP

	pseudo[9] = 6 // Protocol TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-tcpOffset))

	tcpData := packet[tcpOffset:]
	fullData := append(pseudo, tcpData...)

	checksum := calculateChecksum(fullData)
	packet[tcpOffset+16] = byte(checksum >> 8)
	packet[tcpOffset+17] = byte(checksum & 0xFF)
}

// calculateChecksum вычисляет контрольную сумму для TCP/UDP
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func makeFakeQUICInitial(original []byte) []byte {
	// Базовый fake QUIC Initial (из byedpi quic.c, упрощённо)
	fake := make([]byte, 1200) // типичный размер
	fake[0] = 0xc0             // long header + Initial

	// DCID/SCID random
	rand.Read(fake[1:9])                              // version
	binary.BigEndian.PutUint32(fake[1:5], 0x00000001) // QUIC v1

	// SCID/DCID lengths
	fake[5] = 8 // DCID len

	rand.Read(fake[6:14])

	fake[14] = 0 // SCID len 0 for Initial

	// Token len=0
	fake[15] = 0

	// Payload len varint (упрощённо)
	fake[16] = 0x40 | byte(1182&0x3f) // 2-byte varint
	fake[17] = byte(1182 >> 6)

	// Fake payload (CHLO-like)
	copy(fake[18:], []byte("\x06\x00\x40\xf1\x01")) // frame type + etc
	rand.Read(fake[23:])                            // random fill
	return fake
}

// Вспомогательная функция
func getTCPSeq(pkt []byte) uint32 {
	ipLen := int(pkt[0]&0x0F) * 4
	return binary.BigEndian.Uint32(pkt[ipLen+4:])
}

// sendPacket (фикс: удалён дубликат Send)
func (p *Pipeline) sendPacket(data []byte, addr []byte) bool {
	if len(data) < 20 {
		log.Printf("WARNING: Attempted to send packet too short (%d bytes)", len(data))
		return false
	}

	if addr == nil || len(addr) == 0 {
		if _, ok := p.sender.(*sender.RawSender); ok {
			log.Printf("ERROR: WinDivert requires valid addr, skipping send")
			return false
		}
		log.Printf("WARNING: addr is empty, sending without address")
	}

	if err := p.sender.Send(data, addr); err != nil {
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
				// Determine success before building the result struct
				success := !(result.Delay > 500 || len(result.ModifiedPackets) == 0)

				strategyResult := &strategy.StrategyResult{
					StrategyID:   result.StrategyID,
					Success:      success,
					ResponseTime: time.Duration(result.Delay) * time.Millisecond,
					BytesSent:    len(result.ModifiedPackets) * 1500,
					PacketsSent:  len(result.ModifiedPackets),
					Timestamp:    time.Now(),
				}

				if !success {
					invalidated := p.ipCache.InvalidateByStrategy(result.StrategyID)
					if invalidated > 0 {
						log.Printf("Invalidated %d cache entries due to strategy %d failure", invalidated, result.StrategyID)
					}
				}

				p.strategyMgr.ReportResult(strategyResult)
			}
		}
	}
}

// extractIPs извлекает IP-адреса из пакета (копирует, не алиасирует)
func (p *Pipeline) extractIPs(packet []byte) (srcIP, dstIP net.IP, err error) {
	if len(packet) < 20 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	version := packet[0] >> 4
	if version == 4 {
		src := make(net.IP, 4)
		dst := make(net.IP, 4)
		copy(src, packet[12:16])
		copy(dst, packet[16:20])
		return src, dst, nil
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

// setIPTTL + recalculate in one (optimized)
func setIPTTL(packet []byte, ttl int) error {
	if len(packet) < 20 || (packet[0]>>4 != 4) {
		return nil
	}

	packet[8] = byte(ttl)

	// Пересчитываем контрольную сумму
	recalculateIPChecksum(packet)

	return nil
}

// recalculateIPChecksum пересчитывает контрольную сумму IP-заголовка
func recalculateIPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Обнуляем текущую контрольную сумму
	packet[10] = 0
	packet[11] = 0

	// Вычисляем новую
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(packet[10:12], checksum)
}
