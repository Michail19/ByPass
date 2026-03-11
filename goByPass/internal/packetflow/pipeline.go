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
	workers     int
	// workerChans — один канал на воркер (flow affinity).
	// Пакеты одного TCP-потока всегда попадают в один и тот же канал по
	// hash(srcIP, dstIP, srcPort, dstPort) % workers.
	// Это гарантирует:
	//   1) состояние flow (IsHandshakeModified, DataPacketsModified) меняется
	//      только из одной goroutine → не нужна блокировка на hot path;
	//   2) порядок отправки внутри потока сохраняется → нет duplicate ACK / retransmission.
	workerChans []chan capture.Packet
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

	// Создаём отдельный канал на каждый воркер.
	// Размер каждого канала = PacketQueueSize / workers, минимум 256.
	perWorkerQueue := cfg.PacketQueueSize / cfg.Workers
	if perWorkerQueue < 256 {
		perWorkerQueue = 256
	}
	workerChans := make([]chan capture.Packet, cfg.Workers)
	for i := range workerChans {
		workerChans[i] = make(chan capture.Packet, perWorkerQueue)
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
		workerChans: workerChans,
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

	for _, ch := range p.workerChans {
		close(ch)
	}
	close(p.resultChan)
}

// packetForwarder читает пакеты из capturer и направляет их в нужный воркер-канал.
// Маршрутизация по hash(flow) % workers обеспечивает flow affinity:
// один TCP-поток → один воркер → строгий порядок отправки.
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

			// Быстро вычисляем индекс воркера из IP-заголовка (без аллокаций)
			workerIdx := p.hashPacketToWorker(packet.Data)
			ch := p.workerChans[workerIdx]

			select {
			case ch <- packet:
				// Успешно поставлен в очередь нужного воркера
			default:
				// Канал воркера переполнен — дропаем пакет.
				// tempBuffer (старое решение) был опасен: 100 пакетов накапливались
				// и потом выстреливали burst'ом, ломая TCP pacing.
				// Дроп честнее: TCP retransmit восстановит потерянное.
				p.updateStats(func(stats *PipelineStats) {
					stats.PacketsDropped++
				})
				log.Printf("WARNING: Worker %d queue full, dropping packet", workerIdx)
			}
		}
	}
}

// hashPacketToWorker вычисляет индекс воркера для пакета на основе 5-tuple.
// Использует XOR-хэш — без аллокаций, O(1), достаточно равномерный.
func (p *Pipeline) hashPacketToWorker(data []byte) int {
	if p.workers <= 1 || len(data) < 20 {
		return 0
	}
	// Берём srcIP (12:16), dstIP (16:20), srcPort (transport+0), dstPort (transport+2)
	var h uint32
	h = uint32(data[12])<<24 | uint32(data[13])<<16 | uint32(data[14])<<8 | uint32(data[15])  // srcIP
	h ^= uint32(data[16])<<24 | uint32(data[17])<<16 | uint32(data[18])<<8 | uint32(data[19]) // dstIP

	ihl := int(data[0]&0x0F) * 4
	if len(data) >= ihl+4 {
		h ^= uint32(data[ihl])<<8 | uint32(data[ihl+1])   // srcPort
		h ^= uint32(data[ihl+2])<<8 | uint32(data[ihl+3]) // dstPort
	}
	return int(h % uint32(p.workers))
}

// worker обрабатывает пакеты из своего канала.
// Каждый воркер читает только из workerChans[id] — это гарантирует,
// что один TCP-поток обрабатывается строго одним воркером (flow affinity).
func (p *Pipeline) worker(id int) {
	defer p.wg.Done()

	log.Printf("Worker %d started", id)
	ch := p.workerChans[id]

	for {
		select {
		case <-p.ctx.Done():
			return
		case packet, ok := <-ch:
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

	// UDP 443 = QUIC: инжектируем fake QUIC Initial из .bin перед реальным пакетом.
	//
	// Стратегия zapret для QUIC:
	//   - НЕ модифицируем реальный QUIC-пакет (encrypted + packet-number based)
	//   - Отправляем N копий fake QUIC Initial (из quic_initial_www_google_com.bin)
	//     перед реальным пакетом — DPI видит мусор и теряет контекст
	//   - Реальный пакет реинжектируется без изменений
	//
	// Fake-пакет: строится как полный IP+UDP пакет с заменёнными src/dst из оригинала.
	// fixUDPChecksum обязателен — без него сервер/DPI дропнет пакет silently.
	if protocol == 17 {
		if dstPort == 443 {
			strat := p.strategyMgr.SelectStrategy(dstIP.String(), "", 443, "udp")
			if strat != nil && strat.NeedsQUICFake() {
				repeats := strat.FakeQUICRepeats
				if repeats <= 0 {
					repeats = 6
				}
				for i := 0; i < repeats; i++ {
					fakePkt := buildFakeQUICPacket(pkt.Data, strat.FakeQUICFileData)
					if fakePkt != nil {
						p.sendPacket(fakePkt, pkt.Addr)
						p.updateStats(func(stats *PipelineStats) { stats.PacketsModified++ })
					}
				}
			}
		}
		// Реальный UDP-пакет реинжектируем без изменений
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	if !flow.IsAnalyzed {
		info, err := p.analyzer.Analyze(pkt.Data, srcIP.String(), dstIP.String(), srcPort, dstPort)
		if err == nil && info != nil {
			if info.SNI != "" {
				flow.SetHostname(info.SNI)
				flow.IsAnalyzed = true
				// ВАЖНО: обнуляем счётчик — он использовался как analysis-attempt counter,
				// а теперь будет использоваться для подсчёта модифицированных data-пакетов.
				// Без сброса стратегия решит, что уже N пакетов модифицировано.
				flow.Mu.Lock()
				flow.DataPacketsModified = 0
				flow.Mu.Unlock()
			} else if info.Host != "" {
				flow.SetHostname(info.Host)
				flow.IsAnalyzed = true
				flow.Mu.Lock()
				flow.DataPacketsModified = 0
				flow.Mu.Unlock()
			}
			if info.IsTLS {
				flow.SetTLS()
			}
			if info.IsHTTP {
				flow.SetHTTP()
			}
		}
		// Отказываемся от анализа после 4 пакетов без результата.
		// Используем отдельный lock-секции чтобы не смешивать счётчики.
		if !flow.IsAnalyzed {
			flow.Mu.Lock()
			flow.DataPacketsModified++ // временно: счётчик попыток анализа
			giveUp := flow.DataPacketsModified >= 4
			if giveUp {
				flow.IsAnalyzed = true
				flow.DataPacketsModified = 0 // сброс для реального использования ниже
			}
			flow.Mu.Unlock()
		}
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

	// 3. Финальный fallback: SelectStrategy вернула nil —
	//    нет подходящей стратегии для этого IP/hostname/порта.
	//    Просто реинжектируем пакет без модификаций (passthrough).
	if strats == nil {
		log.Printf("[STRATEGY] No strategy for %s:%d (hostname: '%s') — passthrough",
			dstIP.String(), dstPort, flow.Hostname)
		p.sendPacket(pkt.Data, pkt.Addr)
		return
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

// buildFakeQUICPacket строит полный IP+UDP пакет с payload из quicPayload.
//
// Копирует IP и UDP заголовки из оригинального пакета (src/dst IP:port),
// подставляет quicPayload как тело UDP, пересчитывает все длины и checksums.
//
// DPI видит fake QUIC Initial и теряет контекст перед реальным пакетом.
// Реальный пакет реинжектируется без изменений после всех fake.
//
// Требования к quicPayload: содержимое quic_initial_*.bin — захваченный
// QUIC Initial пакет (только QUIC payload, без IP/UDP заголовков).
func buildFakeQUICPacket(original []byte, quicPayload []byte) []byte {
	if len(original) < 28 || len(quicPayload) == 0 {
		return nil
	}
	if original[9] != 17 { // not UDP
		return nil
	}

	ipHdrLen := int(original[0]&0x0F) * 4
	if len(original) < ipHdrLen+8 {
		return nil
	}

	// Строим: IP header (ipHdrLen) + UDP header (8) + quicPayload
	totalLen := ipHdrLen + 8 + len(quicPayload)
	pkt := make([]byte, totalLen)

	// IP заголовок из оригинала (src/dst IP, TTL и т.д.)
	copy(pkt[:ipHdrLen], original[:ipHdrLen])
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// Новый IP ID чтобы не конфликтовать с оригиналом
	pkt[4] = 0
	pkt[5] = 0
	// Сбросить DF бит
	pkt[6] = original[6] &^ 0x40
	pkt[7] = original[7]

	// UDP заголовок: src/dst порты из оригинала
	copy(pkt[ipHdrLen:ipHdrLen+4], original[ipHdrLen:ipHdrLen+4])
	udpLen := uint16(8 + len(quicPayload))
	binary.BigEndian.PutUint16(pkt[ipHdrLen+4:], udpLen)
	pkt[ipHdrLen+6] = 0 // checksum placeholder
	pkt[ipHdrLen+7] = 0

	// QUIC payload
	copy(pkt[ipHdrLen+8:], quicPayload)

	// Пересчитываем checksums
	recalculateIPChecksum(pkt)
	fixUDPChecksum(pkt)

	return pkt
}

// fixUDPChecksum пересчитывает UDP checksum (псевдозаголовок IPv4 + UDP).
func fixUDPChecksum(packet []byte) {
	if len(packet) < 28 {
		return
	}
	ipHdrLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHdrLen+8 {
		return
	}
	udpOffset := ipHdrLen
	packet[udpOffset+6] = 0
	packet[udpOffset+7] = 0

	udpLen := len(packet) - udpOffset
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], packet[12:16])
	copy(pseudo[4:8], packet[16:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))

	full := append(pseudo, packet[udpOffset:]...)
	cs := calculateChecksum(full)
	packet[udpOffset+6] = byte(cs >> 8)
	packet[udpOffset+7] = byte(cs & 0xFF)
}

// Вспомогательная функция
func getTCPSeq(pkt []byte) uint32 {
	ipLen := int(pkt[0]&0x0F) * 4
	return binary.BigEndian.Uint32(pkt[ipLen+4:])
}

// sendPacket отправляет пакет через sender.
func (p *Pipeline) sendPacket(data []byte, addr []byte) bool {
	if len(data) < 20 {
		log.Printf("WARNING: Attempted to send packet too short (%d bytes)", len(data))
		return false
	}

	// WinDivert требует валидный addr из WinDivertRecv.
	// Если addr пустой — пакет не может быть реинжектирован корректно.
	if len(addr) == 0 {
		log.Printf("ERROR: addr is empty, WinDivert requires original WINDIVERT_ADDRESS — skipping send")
		return false
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

// recalculateIPChecksum пересчитывает контрольную сумму IP-заголовка.
// ВАЖНО: использует IHL (IP Header Length) из байта 0, а не захардкоженные 20.
// IP-опции (IHL > 20) встречаются редко, но игнорирование их приводит к
// неверной checksum и дропу пакета маршрутизатором.
func recalculateIPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl {
		return // некорректный заголовок
	}

	packet[10] = 0
	packet[11] = 0

	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
}
