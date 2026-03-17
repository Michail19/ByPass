package packetflow

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
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
	wgWorkers   sync.WaitGroup
	wgResults   sync.WaitGroup
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
		cfg.PacketQueueSize = 32768
	}
	if cfg.ResultQueueSize <= 0 {
		cfg.ResultQueueSize = 4096
	}

	// Создаём отдельный канал на каждый воркер.
	// Размер каждого канала = PacketQueueSize / workers, минимум 1024.
	perWorkerQueue := cfg.PacketQueueSize / cfg.Workers
	if perWorkerQueue < 1024 {
		perWorkerQueue = 1024
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

	// Передаем пакеты из капчера в канал.
	// ВАЖНО: добавляем в wg ДО запуска — Stop() вызывает wg.Wait() перед close(ch).
	// Без этого Stop() может закрыть workerChans пока packetForwarder ещё пишет в них
	// → panic: send on closed channel (#ForwarderWG).
	p.wg.Add(1)
	go p.packetForwarder()

	log.Printf("Pipeline started with %d workers", p.workers)

	return nil
}

// Stop останавливает конвейер
func (p *Pipeline) Stop() {
	if p == nil {
		return
	}

	if p.cancel != nil {
		p.cancel()
	}

	// Сначала останавливаем capturer, чтобы packetForwarder перестал читать новые пакеты.
	if err := p.capturer.Stop(); err != nil {
		log.Printf("Error stopping capturer: %v", err)
	}

	// Ждём завершения ВСЕХ горутин, которые были добавлены через p.wg:
	//   - workers
	//   - resultProcessor
	//   - packetForwarder
	//
	// Важно: worker'ы и packetForwarder выходят по p.ctx.Done(), а не по close(workerChans),
	// поэтому закрывать workerChans тут не нужно и даже опасно — можно словить send on closed channel.
	p.wg.Wait()

	// После остановки producers/consumers resultChan уже никто не использует,
	// так что закрывать его не требуется.
	// sender закрываем в самом конце.
	if err := p.sender.Close(); err != nil {
		log.Printf("Error closing sender: %v", err)
	}
}

// packetForwarder читает пакеты из capturer и направляет их в нужный воркер-канал.
// Маршрутизация по hash(flow) % workers обеспечивает flow affinity:
// один TCP-поток → один воркер → строгий порядок отправки.
func (p *Pipeline) packetForwarder() {
	defer p.wg.Done() // соответствует wg.Add(1) в Start() (#ForwarderWG)
	for {
		select {
		case <-p.ctx.Done():
			return

		case packet, ok := <-p.capturer.Packets():
			if !ok {
				return
			}

			p.updateStats(func(stats *PipelineStats) {
				stats.PacketsReceived++
				stats.LastPacketTime = time.Now()
			})

			// Быстро вычисляем индекс воркера из IP-заголовка (без аллокаций)
			workerIdx := p.hashPacketToWorker(packet.Data)
			ch := p.workerChans[workerIdx]

			// Приоритетный dispatch для SYN и TLS ClientHello (#6).
			// При переполнении очереди data-пакеты дропаются сразу (TCP retransmit восстановит).
			// SYN и ClientHello дропать нельзя: браузер ждёт retransmit timeout (1-3 сек)
			// прежде чем повторить — это видимый пользователю фриз при каждом открытии страницы.
			if isHandshakePacket(packet.Data) {
				// Блокирующий send с таймаутом 2ms для handshake пакетов (SYN, ClientHello).
				// Дропать handshake нельзя: браузер ждёт TCP retransmit (1-3с) → видимый фриз.
				// 2ms = достаточно чтобы воркер разгрузился при временной нагрузке.
				// BUG FIX: было закомментировано → немедленный дроп при полной очереди →
				// ClientHello дропались → TLS handshake не завершался → сайты не грузились.
				select {
				case ch <- packet:
				case <-time.After(20 * time.Millisecond):
					p.updateStats(func(stats *PipelineStats) { stats.PacketsDropped++ })
					log.Printf("WARNING: Worker %d queue full, dropping handshake packet", workerIdx)
				}
			} else {
				// Для обычных data-пакетов тоже даём короткое окно ожидания.
				// Немедленный drop слишком болезнен для интерактивных TLS-сессий
				// вроде Telegram Web: retransmit есть, но пользователь видит лаги
				// и "полуживые" чаты.
				select {
				case ch <- packet:
				case <-p.ctx.Done():
					return
				case <-time.After(10 * time.Millisecond):
					p.updateStats(func(stats *PipelineStats) { stats.PacketsDropped++ })
					log.Printf("WARNING: Worker %d queue full, dropping data packet", workerIdx)
				}
			}
		}
	}
}

// hashPacketToWorker вычисляет индекс воркера для пакета на основе 5-tuple.
// Использует XOR-хэш — без аллокаций, O(1), достаточно равномерный.
// isHandshakePacket быстро определяет что пакет — SYN или TLS ClientHello (#6).
// Используется при dispatch чтобы дать handshake пакетам приоритет перед data пакетами.
// Намеренно inline и без аллокаций — вызывается в hot path packetForwarder.
//
// Детектируем:
//   - TCP SYN: isSYN флаг в TCP заголовке (flags & 0x02)
//   - TLS ClientHello: ContentType=0x16 (Handshake) + HandshakeType=0x01 (ClientHello)
func isHandshakePacket(data []byte) bool {
	if len(data) < 20 || data[0]>>4 != 4 {
		return false
	}
	proto := data[9]
	if proto != 6 { // только TCP
		return false
	}
	ihl := int(data[0]&0x0F) * 4
	if len(data) < ihl+20 {
		return false
	}
	flags := data[ihl+13]
	if flags&0x02 != 0 { // SYN
		return true
	}
	// TLS ClientHello: payload[0]=0x16, payload[5]=0x01
	tcpHdrLen := int(data[ihl+12]>>4) * 4
	payloadOffset := ihl + tcpHdrLen
	if len(data) >= payloadOffset+6 &&
		data[payloadOffset] == 0x16 && // TLS ContentType: Handshake
		data[payloadOffset+1] == 0x03 && // TLS major version
		data[payloadOffset+5] == 0x01 { // HandshakeType: ClientHello
		return true
	}
	return false
}

func strategyAllowsPacketType(
	s *strategy.Strategy,
	isSYN bool,
	isACK bool,
	isClientHello bool,
	isData bool,
) bool {
	if s == nil || len(s.ApplyToPacketTypes) == 0 {
		return true
	}

	allowed := make(map[string]bool, len(s.ApplyToPacketTypes))
	for _, t := range s.ApplyToPacketTypes {
		allowed[strings.ToLower(strings.TrimSpace(t))] = true
	}

	// SYN / ClientHello считаем handshake-пакетами
	if isSYN || isClientHello {
		return allowed["handshake"] || allowed["syn"] || allowed["tls"]
	}

	// Чистый ACK без payload
	if isACK && !isData {
		return allowed["ack"]
	}

	// Data / appdata
	if isData {
		return allowed["data"] || allowed["appdata"] || allowed["payload"]
	}

	return true
}

func (p *Pipeline) hashPacketToWorker(data []byte) int {
	if p.workers <= 1 || len(data) < 20 {
		return 0
	}
	// Берём srcIP (12:16), dstIP (16:20), srcPort (transport+0), dstPort (transport+2)
	var h uint32
	h = uint32(data[12])<<24 | uint32(data[13])<<16 | uint32(data[14])<<8 | uint32(data[15])  // srcIP
	h ^= uint32(data[16])<<24 | uint32(data[17])<<16 | uint32(data[18])<<8 | uint32(data[19]) // dstIP
	h ^= uint32(data[9]) << 24

	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl {
		return int(h % uint32(p.workers))
	}
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

	defer func() {
		processTime := time.Since(startTime)
		p.updateStats(func(stats *PipelineStats) {
			stats.PacketsProcessed++
			stats.TotalProcessTime += processTime
			if stats.PacketsProcessed > 0 {
				stats.AvgProcessTime = stats.TotalProcessTime / time.Duration(stats.PacketsProcessed)
			}
		})
	}()

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

	// Поддерживаем в pipeline только TCP и UDP.
	if protocol != 6 && protocol != 17 {
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	// NEW: пассивно разбираем DNS-ответы и seed-им кэши
	if protocol == 17 && (srcPort == 53 || dstPort == 53) {
		p.maybeSeedCachesFromDNS(pkt.Data)
	}

	// Получаем или создаём поток
	flow := p.conntrack.GetOrCreate(srcIP, dstIP, srcPort, dstPort, protocol)

	// Буферизуем TLS fragments только для client->server
	isClientDir := srcIP.String() == flow.SrcIPStr && srcPort == flow.Key.SrcPort

	// --- Минимальный reassembly для TLS ClientHello ---
	// Сохраняем только TLS-похожие фрагменты, чтобы при фрагментации ClientHello
	// попытаться извлечь SNI из нескольких TCP сегментов.
	if protocol == 6 && isClientDir {
		p.maybeBufferTLSFragments(flow, pkt.Data)
	}

	// Читаем flow.Hostname один раз под RLock — устраняет data race с SetHostname().
	// Все последующие обращения к hostname используют эту локальную копию.
	flow.Mu.RLock()
	flowHostname := flow.Hostname
	flow.Mu.RUnlock()

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
			// Передаём flow.Hostname вместо "":
			//   - Если flow уже имеет hostname (из предыдущего TCP-соединения к тому же IP,
			//     или если QUIC-поток позже обновит hostname) — testOverride из Discovery
			//     корректно применится.
			//   - SelectStrategy приоритет: testOverride (по hostname) → isGoogleIP (по IP) →
			//     bestForProtocol. Если hostname пуст — isGoogleIP всё равно сработает.
			strat := p.strategyMgr.SelectStrategy(dstIP.String(), flowHostname, 443, "udp")
			if strat != nil && strat.NeedsQUICFake() {
				// Inject fake QUIC Initial только для первых пакетов handshake.
				// QUIC-соединение: 1-2 Initial пакета → handshake → тысячи data пакетов.
				// Без ограничения: 6 fake × тысячи пакетов = throughput collapse.
				flow.Mu.Lock()
				doBurst := flow.QUICFakeBursts < 2
				if doBurst {
					flow.QUICFakeBursts++
				}
				flow.Mu.Unlock()

				if doBurst {
					repeats := strat.FakeQUICRepeats
					if repeats <= 0 {
						repeats = 6
					}
					// TTL для fake QUIC: используем QUICttl если задан, иначе FakeTTL.
					// Без TTL ограничения fake пакет доходит до Google QUIC сервера (TTL=64/128),
					// Google может ответить Stateless Reset → connection retry → slow start.
					// Цель: пакет доходит до DPI (1-3 hop), умирает до сервера (~6-10 hop).
					fakeTTL := strat.QUICttl
					if fakeTTL <= 0 {
						fakeTTL = strat.FakeTTL
					}
					if fakeTTL <= 0 {
						fakeTTL = 6 // zapret default: TTL=6
					}
					for i := 0; i < repeats; i++ {
						fakePkt := buildFakeQUICPacket(pkt.Data, strat.FakeQUICFileData, fakeTTL)
						if fakePkt != nil {
							if p.sendModifiedPacket(fakePkt, pkt.Addr) {
								p.updateStats(func(stats *PipelineStats) {
									stats.PacketsModified++
									stats.PacketsSent++
								})
							}
						}
					}
				}
			}
		}
		// Реальный UDP-пакет реинжектируем без изменений
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	// Быстрое чтение IsAnalyzed под RLock — flow.Mu защищает все поля Flow,
	// включая IsAnalyzed. Без блокировки Go race detector фиксирует data race
	// с cleanupLoop и другими читателями (#5 в review).
	flow.Mu.RLock()
	isAnalyzed := flow.IsAnalyzed
	flow.Mu.RUnlock()

	if !isAnalyzed {
		info, err := p.analyzer.Analyze(pkt.Data, srcIP.String(), dstIP.String(), srcPort, dstPort)
		if err == nil && info != nil {
			if info.SNI != "" {
				flow.SetHostname(info.SNI)
				flowHostname = info.SNI // обновляем локальную копию
				flow.Mu.Lock()
				flow.IsAnalyzed = true
				flow.AnalyzeMisses = 0
				flow.DataPacketsModified = 0
				flow.Mu.Unlock()
			} else if info.Host != "" {
				flow.SetHostname(info.Host)
				flowHostname = info.Host // обновляем локальную копию
				flow.Mu.Lock()
				flow.IsAnalyzed = true
				flow.AnalyzeMisses = 0
				flow.DataPacketsModified = 0
				flow.Mu.Unlock()
			}

			// Если это TLS handshake, но SNI не извлечён (PossibleFragment / разрыв по TCP),
			// пробуем собрать буфер из сохранённых фрагментов.
			if flowHostname == "" && info.IsTLS && info.IsHandshake {
				if sni := tryExtractSNIFromFlowBuffer(flow); sni != "" {
					flow.SetHostname(sni)
					flowHostname = sni
					flow.Mu.Lock()
					flow.IsAnalyzed = true
					flow.AnalyzeMisses = 0
					flow.DataPacketsModified = 0
					flow.Mu.Unlock()
				}
			}

			if info.IsTLS {
				flow.SetTLS()
			}
			if info.IsHTTP {
				flow.SetHTTP()
			}
		}
		// Отказываемся от анализа после 4 пакетов без результата.
		flow.Mu.Lock()
		if !flow.IsAnalyzed {
			flow.AnalyzeMisses++
			if flow.AnalyzeMisses >= 4 {
				flow.IsAnalyzed = true
				flow.AnalyzeMisses = 0
			}
		}
		flow.Mu.Unlock()
	}

	// Обновляем локальную копию после первого прохода анализа,
	// иначе ниже bypass-блок может повторно вызвать Analyze() на том же пакете.
	flow.Mu.RLock()
	isAnalyzed = flow.IsAnalyzed
	flow.Mu.RUnlock()

	// Проверяем кэш
	var shouldBypass bool
	var strategyID int
	var strats *strategy.Strategy
	cachedStratID := 0
	var cached *cache.IPCacheEntry

	if c, exists := p.ipCache.GetByIP(dstIP); exists {
		cached = c
		cachedStratID = c.StrategyID
		shouldBypass = c.ShouldBypass
		strategyID = c.StrategyID
		p.updateStats(func(stats *PipelineStats) { stats.CacheHits++ })
	}

	// 1. Свежий выбор по hostname/IP
	selectorHostname := flowHostname
	selectorFromCache := false

	if selectorHostname == "" && cached != nil && cached.Hostname != "" {
		selectorHostname = cached.Hostname
		selectorFromCache = true
	}

	var fresh *strategy.Strategy
	if selectorFromCache {
		fresh = p.strategyMgr.SelectStrategyForBareIPCachedHost(
			dstIP.String(),
			selectorHostname,
			int(dstPort),
			"tcp",
		)
	} else {
		fresh = p.strategyMgr.SelectStrategy(
			dstIP.String(),
			selectorHostname,
			int(dstPort),
			"tcp",
		)
	}

	// 2. Если hostname ещё не известен, reuse cached non-passthrough ТОЛЬКО
	// для выделенных bypass-hostname. Shared hostnames не "приклеиваем".
	preferCached := flowHostname == "" &&
		cached != nil &&
		cachedStratID > 1 &&
		shouldReuseBypassFromIPCache(cached.Hostname, cachedStratID)

	switch {
	case preferCached && (fresh == nil || fresh.ID == 1):
		if s, ok := p.strategyMgr.GetStrategy(cachedStratID); ok && s != nil {
			strats = s
			strategyID = s.ID
			shouldBypass = cached.ShouldBypass
		}

	case fresh != nil:
		strats = fresh
		strategyID = fresh.ID
		shouldBypass = fresh.ID != 1

		if selectorHostname != "" &&
			shouldPersistBypassStrategyByIP(selectorHostname, strategyID) &&
			(cached == nil || strategyID != cachedStratID || !strings.EqualFold(selectorHostname, cached.Hostname)) {
			p.ipCache.PutByIP(dstIP, selectorHostname, shouldBypass, strategyID)
		}

	case cached != nil && cachedStratID > 0:
		// используем то, что уже лежит в кэше, включая strategy 1
		if s, ok := p.strategyMgr.GetStrategy(cachedStratID); ok && s != nil {
			strats = s
			strategyID = s.ID
			shouldBypass = cached.ShouldBypass
		}
	}

	// 3. Если всё ещё nil — подставляем passthrough как явную стратегию,
	// а не оставляем "пустое решение".
	if strats == nil {
		if s, ok := p.strategyMgr.GetStrategy(1); ok && s != nil {
			strats = s
			strategyID = 1
			shouldBypass = false
		}
	}

	// 4. Финальный лог — только ПОСЛЕ того как strats уже определена
	finalStrategyID := 0
	finalStrategyName := "nil"
	if strats != nil {
		finalStrategyID = strats.ID
		finalStrategyName = strats.Name
	}
	log.Printf("[PIPELINE] Final strategy hostname=%q ip=%s:%d -> id=%d (%s), bypass=%v, cached=%v",
		flowHostname, dstIP.String(), dstPort, finalStrategyID, finalStrategyName, shouldBypass, cached != nil)

	// Совсем аварийный fallback — только если даже strategy 1 не найдена
	if strats == nil {
		p.sendPacket(pkt.Data, pkt.Addr)
		return
	}

	if shouldBypass {
		// До блока анализа вычисли эти признаки один раз
		ipHeaderLen := int(pkt.Data[0]&0x0F) * 4
		tcpOffset := ipHeaderLen

		if len(pkt.Data) < tcpOffset+14 {
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}

		tcpHeaderLen := int(pkt.Data[tcpOffset+12]>>4) * 4
		payloadOffset := tcpOffset + tcpHeaderLen
		hasPayload := len(pkt.Data) > payloadOffset

		looksClientHello := hasPayload &&
			len(pkt.Data) >= payloadOffset+6 &&
			pkt.Data[payloadOffset] == 0x16 &&
			pkt.Data[payloadOffset+1] == 0x03 &&
			pkt.Data[payloadOffset+5] == 0x01

		forceAnalyze := flowHostname == "" && looksClientHello

		if !isAnalyzed || forceAnalyze {
			info, err := p.analyzer.Analyze(pkt.Data, srcIP.String(), dstIP.String(), srcPort, dstPort)
			if err == nil && info != nil {
				if info.SNI != "" {
					flow.SetHostname(info.SNI)
					flowHostname = info.SNI
					flow.Mu.Lock()
					flow.IsAnalyzed = true
					flow.AnalyzeMisses = 0
					flow.DataPacketsModified = 0
					flow.Mu.Unlock()
				} else if info.Host != "" {
					flow.SetHostname(info.Host)
					flowHostname = info.Host
					flow.Mu.Lock()
					flow.IsAnalyzed = true
					flow.AnalyzeMisses = 0
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

			// Отказываемся от анализа только после 4 payload-пакетов без результата.
			flow.Mu.Lock()
			if !flow.IsAnalyzed && hasPayload {
				flow.AnalyzeMisses++
				if flow.AnalyzeMisses >= 4 && !looksClientHello {
					flow.IsAnalyzed = true
					flow.AnalyzeMisses = 0
				}
			}
			flow.Mu.Unlock()
		}

		flags := pkt.Data[tcpOffset+13]
		isSYN := (flags & 0x02) != 0
		isACK := (flags & 0x10) != 0
		isData := len(pkt.Data) > payloadOffset
		isClientHello := isData &&
			len(pkt.Data) >= payloadOffset+6 &&
			pkt.Data[payloadOffset] == 0x16 && // TLS Handshake record
			pkt.Data[payloadOffset+1] == 0x03 && // TLS major version
			pkt.Data[payloadOffset+5] == 0x01 // ClientHello

		// Для TLS-only syndata профилей по умолчанию не применяем SYN-data,
		// пока у flow ещё нет hostname/SNI.
		//
		// Исключение: если hostname пришёл из IP-cache и это именно YouTube CDN
		// (googlevideo / c.youtube), разрешаем ранний SYN-data.
		// Для main/control YouTube-hostов этого НЕ делаем — они уже downgraded
		// через SelectStrategyForBareIPCachedHost.
		allowBareCachedCDNSynData := isSYN &&
			flowHostname == "" &&
			selectorFromCache &&
			strats != nil &&
			strats.ID == 31 &&
			strats.SynData &&
			strats.ApplyToTLS &&
			!strats.ApplyToHTTP &&
			!strats.AnyProtocol &&
			strategy.IsYouTubeCDNHostname(selectorHostname)

		skipBareSynData := isSYN &&
			flowHostname == "" &&
			strats != nil &&
			strats.SynData &&
			strats.ApplyToTLS &&
			!strats.ApplyToHTTP &&
			!strats.AnyProtocol &&
			!allowBareCachedCDNSynData

		if allowBareCachedCDNSynData {
			log.Printf(
				"[PIPELINE] Allow bare-IP SYN-data for cached YouTube CDN strategy %d (%s) ip=%s:%d host=%q",
				strats.ID, strats.Name, dstIP.String(), dstPort, selectorHostname,
			)
		}

		if skipBareSynData {
			log.Printf(
				"[PIPELINE] Skip bare-IP SYN-data for strategy %d (%s) ip=%s:%d; waiting for SNI/Host (flow_host=%q selector_host=%q)",
				strats.ID, strats.Name, dstIP.String(), dstPort, flowHostname, selectorHostname,
			)
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}

		packetTypeAllowed := strategyAllowsPacketType(strats, isSYN, isACK, isClientHello, isData)

		// Для TLS-only стратегий модифицируем только SYN и ClientHello.
		modifyAppData := false
		if packetTypeAllowed && isData && !isClientHello {
			if strats.AnyProtocol || strats.ApplyToHTTP {
				modifyAppData = (strats.ModifyFirstDataPackets > 0 &&
					flow.DataPacketsModified < strats.ModifyFirstDataPackets) ||
					(strats.ModifyFirstDataPackets == 0)
			}
		}

		attemptedAppDataMod := modifyAppData

		applyMods := packetTypeAllowed && ((isSYN && strats.SynData) ||
			(isClientHello && strats.ApplyToTLS) ||
			modifyAppData)

		if applyMods {
			flow.Mu.Lock()
			if isClientHello {
				flow.IsHandshakeModified = true // tracking only, не влияет на следующие пакеты
			}
			// Increment перенесён ниже, после успеха
			flow.Mu.Unlock()
		}

		if !applyMods {
			// Пропускаем data-пакеты без модификаций
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}

		// Только здесь применяем модификации
		result, err := p.pktModifier.ModifyPacket(pkt.Data, flow, strats)
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
		validModified := 0
		sentModified := 0

		if len(result.ModifiedPackets) > 0 {
			for _, modPkt := range result.ModifiedPackets {
				if len(modPkt) < 20 || (modPkt[0]>>4 != 4) {
					continue
				}

				validModified++

				if p.sendModifiedPacket(modPkt, pkt.Addr) {
					sentModified++
					p.updateStats(func(stats *PipelineStats) {
						stats.PacketsModified++
						stats.PacketsSent++
					})
				}
			}

			// Считаем пакет реально модифицированным только если ушли ВСЕ
			// модифицированные части. Иначе flow state не трогаем — чтобы
			// ретрансмит смог ещё раз попробовать bypass.
			if validModified > 0 && sentModified == validModified {
				flow.Mu.Lock()
				if attemptedAppDataMod {
					flow.DataPacketsModified++
				}
				if isClientHello {
					flow.IsHandshakeModified = true
				}
				flow.Mu.Unlock()
			}

			// Критический fallback:
			// если стратегия заменяет оригинал (SendOriginal=false), но хотя бы
			// одна модифицированная часть не отправилась — отправляем original,
			// иначе трафик просто пропадёт.
			if !result.SendOriginal && (validModified == 0 || sentModified < validModified) {
				log.Printf(
					"[STRATEGY] Modified send incomplete for strategy %d: sent=%d/%d, fallback to original",
					strategyID, sentModified, validModified,
				)

				if p.sendPacket(pkt.Data, pkt.Addr) {
					p.updateStats(func(stats *PipelineStats) {
						stats.PacketsSent++
					})
				}
				return
			}
		}

		// Репортим итог применения стратегии в асинхронный resultProcessor.
		if p.strategyMgr != nil && result.StrategyID != 0 {
			result.Delay = int(time.Since(startTime).Milliseconds())

			select {
			case p.resultChan <- *result:
			default:
				log.Printf("[STRATEGY] resultChan full, dropping result for strategy %d", result.StrategyID)
			}
		}

		// Отправляем оригинал (если нужно)
		if result.SendOriginal {
			if p.sendPacket(pkt.Data, pkt.Addr) {
				p.updateStats(func(stats *PipelineStats) {
					stats.PacketsSent++
				})
			}
		}
	} else {
		p.sendPacket(pkt.Data, pkt.Addr)
	}
}

// maybeBufferTLSFragments сохраняет в flow.ClientData только фрагменты,
// похожие на TLS ClientHello record / handshake fragment.
// Это снижает память по сравнению с буферизацией всего TCP payload (видео/стрим).
func (p *Pipeline) maybeBufferTLSFragments(flow *conntrack.Flow, ipPacket []byte) {
	if flow == nil || len(ipPacket) < 40 || (ipPacket[0]>>4 != 4) {
		return
	}

	ipHdrLen := int(ipPacket[0]&0x0F) * 4
	if len(ipPacket) < ipHdrLen+20 {
		return
	}

	tcpHdrLen := int(ipPacket[ipHdrLen+12]>>4) * 4
	payloadOffset := ipHdrLen + tcpHdrLen
	if payloadOffset < 0 || payloadOffset >= len(ipPacket) {
		return
	}

	payload := ipPacket[payloadOffset:]
	if len(payload) == 0 {
		return
	}

	looksTLSRecord := len(payload) >= 6 && payload[0] == 0x16 && payload[1] == 0x03
	looksTLSFrag := len(payload) >= 4 && payload[0] == 0x01 // ClientHello handshake fragment heuristic
	if !looksTLSRecord && !looksTLSFrag {
		return
	}

	// Не буферизуем бесконечно — только до 4096 байт фрагмента.
	if len(payload) > 4096 {
		payload = payload[:4096]
	}

	seq := binary.BigEndian.Uint32(ipPacket[ipHdrLen+4 : ipHdrLen+8])
	ack := binary.BigEndian.Uint32(ipPacket[ipHdrLen+8 : ipHdrLen+12])
	flow.Update(true, seq, ack, len(payload), payload)
}

// tryExtractSNIFromFlowBuffer пытается собрать до 4KB TLS-данных из flow.ClientData
// и извлечь SNI по protocol.FindSNI().
func tryExtractSNIFromFlowBuffer(flow *conntrack.Flow) string {
	if flow == nil {
		return ""
	}

	flow.Mu.RLock()
	frags := append([][]byte(nil), flow.ClientData...)
	flow.Mu.RUnlock()

	if len(frags) == 0 {
		return ""
	}

	// Найти первый полноценный TLS record header (0x16 0x03)
	start := -1
	for i := range frags {
		if len(frags[i]) >= 6 && frags[i][0] == 0x16 && frags[i][1] == 0x03 {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}

	// Собираем буфер до 4096 байт
	bufLen := 0
	for i := start; i < len(frags) && bufLen < 4096; i++ {
		bufLen += len(frags[i])
	}
	if bufLen > 4096 {
		bufLen = 4096
	}

	buf := make([]byte, 0, bufLen)
	for i := start; i < len(frags) && len(buf) < 4096; i++ {
		need := 4096 - len(buf)
		chunk := frags[i]
		if len(chunk) > need {
			chunk = chunk[:need]
		}
		buf = append(buf, chunk...)
	}

	namePos, err := protocol.FindSNI(buf)
	if err != nil || namePos < 2 || namePos >= len(buf) {
		return ""
	}

	nameLen := int(binary.BigEndian.Uint16(buf[namePos-2 : namePos]))
	if nameLen <= 0 || namePos+nameLen > len(buf) {
		return ""
	}

	return string(buf[namePos : namePos+nameLen])
}

func (p *Pipeline) maybeSeedCachesFromDNS(packet []byte) {
	if p == nil || p.domainCache == nil || p.ipCache == nil {
		return
	}

	domain, ips, cname, ttl, ok := parseDNSResponse(packet)
	if !ok || domain == "" || len(ips) == 0 {
		return
	}

	p.domainCache.PutWithTTL(domain, ips, cname, ttl)

	for _, ip := range ips {
		if s := p.strategyMgr.SelectStrategy(ip.String(), domain, 443, "tcp"); s != nil && s.ID > 1 {
			p.ipCache.PutByIP(ip, domain, true, s.ID)
		} else {
			p.ipCache.SeedHostnameByIP(ip, domain)
		}
	}

	log.Printf("[DNS] Seeded caches: domain=%s ips=%d ttl=%d cname=%s", domain, len(ips), ttl, cname)
}

func shouldReuseBypassFromIPCache(host string, strategyID int) bool {
	if strategyID <= 1 {
		return false
	}
	return shouldPersistBypassStrategyByIP(host, strategyID)
}

func shouldPersistBypassStrategyByIP(host string, strategyID int) bool {
	if strategyID <= 1 {
		return false
	}

	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}

	// Main/control YouTube-hostы не приклеиваем к IP-cache для раннего bypass.
	// Иначе слишком легко снова получить aggressive strategy на bare-IP TCP.
	if strategy.IsYouTubeControlHostname(h) {
		return false
	}

	switch {
	case strategy.IsYouTubeCDNHostname(h),
		h == "telegram.org",
		h == "web.telegram.org",
		strings.HasSuffix(h, ".telegram.org"),
		h == "t.me",
		strings.HasSuffix(h, ".t.me"):
		return true
	default:
		return false
	}
}

func parseDNSResponse(packet []byte) (domain string, ips []net.IP, cname string, ttl int, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return "", nil, "", 0, false
	}

	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+8 {
		return "", nil, "", 0, false
	}

	proto := packet[9]
	if proto != 17 { // UDP only
		return "", nil, "", 0, false
	}

	udpOffset := ihl
	srcPort := binary.BigEndian.Uint16(packet[udpOffset : udpOffset+2])
	dstPort := binary.BigEndian.Uint16(packet[udpOffset+2 : udpOffset+4])
	if srcPort != 53 && dstPort != 53 {
		return "", nil, "", 0, false
	}

	dnsOffset := udpOffset + 8
	if len(packet) < dnsOffset+12 {
		return "", nil, "", 0, false
	}

	flags := binary.BigEndian.Uint16(packet[dnsOffset+2 : dnsOffset+4])
	qr := (flags & 0x8000) != 0
	if !qr {
		return "", nil, "", 0, false
	}

	qdCount := int(binary.BigEndian.Uint16(packet[dnsOffset+4 : dnsOffset+6]))
	anCount := int(binary.BigEndian.Uint16(packet[dnsOffset+6 : dnsOffset+8]))
	if qdCount <= 0 || anCount <= 0 {
		return "", nil, "", 0, false
	}

	off := dnsOffset + 12

	var err error
	domain, off, err = readDNSName(packet, dnsOffset, off)
	if err != nil || domain == "" {
		return "", nil, "", 0, false
	}

	// skip QTYPE + QCLASS
	if len(packet) < off+4 {
		return "", nil, "", 0, false
	}
	off += 4

	minTTL := 0

	for i := 0; i < anCount; i++ {
		_, off, err = readDNSName(packet, dnsOffset, off)
		if err != nil || len(packet) < off+10 {
			return domain, ips, cname, minTTL, len(ips) > 0
		}

		rtype := binary.BigEndian.Uint16(packet[off : off+2])
		// class := binary.BigEndian.Uint16(packet[off+2 : off+4])
		rttl := int(binary.BigEndian.Uint32(packet[off+4 : off+8]))
		rdlen := int(binary.BigEndian.Uint16(packet[off+8 : off+10]))
		off += 10

		if len(packet) < off+rdlen {
			return domain, ips, cname, minTTL, len(ips) > 0
		}

		if rttl > 0 && (minTTL == 0 || rttl < minTTL) {
			minTTL = rttl
		}

		switch rtype {
		case 1: // A
			if rdlen == 4 {
				ips = append(ips, net.IPv4(packet[off], packet[off+1], packet[off+2], packet[off+3]))
			}
		case 5: // CNAME
			if name, _, err := readDNSName(packet, dnsOffset, off); err == nil {
				cname = name
			}
		}

		off += rdlen
	}

	return domain, ips, cname, minTTL, len(ips) > 0
}

func readDNSName(packet []byte, dnsStart, offset int) (string, int, error) {
	var labels []string
	start := offset
	jumped := false
	seen := 0

	for {
		if offset >= len(packet) {
			return "", start, fmt.Errorf("dns name out of bounds")
		}
		if seen > 20 {
			return "", start, fmt.Errorf("dns compression loop")
		}
		seen++

		l := int(packet[offset])

		if l == 0 {
			offset++
			if !jumped {
				start = offset
			}
			break
		}

		if l&0xC0 == 0xC0 {
			if offset+1 >= len(packet) {
				return "", start, fmt.Errorf("dns pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(packet[offset:offset+2]) & 0x3FFF)

			abs := dnsStart + ptr
			if abs >= len(packet) {
				return "", start, fmt.Errorf("dns pointer out of bounds")
			}

			if !jumped {
				start = offset + 2
			}

			offset = abs
			jumped = true
			continue
		}

		offset++
		if offset+l > len(packet) {
			return "", start, fmt.Errorf("dns label out of bounds")
		}
		labels = append(labels, string(packet[offset:offset+l]))
		offset += l
	}

	return strings.ToLower(strings.Join(labels, ".")), start, nil
}

// fixTCPChecksum пересчитывает TCP checksum без аллокаций (#6).
// Считает checksum streaming-способом: сначала псевдозаголовок, потом TCP данные —
// без make([]byte) и append, которые дают ~2 аллокации на каждый пакет.
func fixTCPChecksum(packet []byte) {
	if len(packet) < 40 {
		return
	}
	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpOffset := ipHeaderLen
	if len(packet) < tcpOffset+20 {
		return
	}

	// Обнуляем поле checksum перед расчётом
	packet[tcpOffset+16] = 0
	packet[tcpOffset+17] = 0

	tcpLen := len(packet) - tcpOffset

	// Счёт ведём как uint32 — overflow складывается обратно
	var sum uint32

	// Псевдозаголовок IPv4: srcIP(4) + dstIP(4) + 0(1) + proto(1) + tcpLen(2)
	sum += uint32(packet[12])<<8 | uint32(packet[13]) // srcIP[0:2]
	sum += uint32(packet[14])<<8 | uint32(packet[15]) // srcIP[2:4]
	sum += uint32(packet[16])<<8 | uint32(packet[17]) // dstIP[0:2]
	sum += uint32(packet[18])<<8 | uint32(packet[19]) // dstIP[2:4]
	sum += uint32(6)                                  // protocol = TCP
	sum += uint32(tcpLen)                             // TCP segment length

	// TCP заголовок + данные
	tcp := packet[tcpOffset:]
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}

	// Свёртка
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	cs := ^uint16(sum)

	if cs == 0 {
		cs = 0xFFFF
	}

	packet[tcpOffset+16] = byte(cs >> 8)
	packet[tcpOffset+17] = byte(cs)
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
// fakeTTL устанавливается явно (#2): должен быть достаточно мал чтобы пакет
// умер до QUIC сервера (~6-10 hop), но дошёл до DPI (обычно 1-3 hop от клиента).
// Без TTL ограничения Google QUIC сервер получает fake, парсит его, отвечает
// Stateless Reset → браузер делает connection retry → slow start.
//
// DPI видит fake QUIC Initial и теряет контекст перед реальным пакетом.
// Реальный пакет реинжектируется без изменений после всех fake.
func buildFakeQUICPacket(original []byte, quicPayload []byte, fakeTTL int) []byte {
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
	pkt := make([]byte, ipHdrLen+8+len(quicPayload))

	// IP заголовок из оригинала (src/dst IP, TTL и т.д.)
	copy(pkt[:ipHdrLen], original[:ipHdrLen])
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// IP ID: original+1 — выглядит как следующий пакет в потоке,
	// а не как статичный 0 который легко fingerprint-ится (#7).
	origID := binary.BigEndian.Uint16(original[4:6])
	binary.BigEndian.PutUint16(pkt[4:6], origID+1)
	// Сохраняем DF бит оригинала — fake не должен выделяться несоответствием флагов
	pkt[6] = original[6]
	pkt[7] = original[7]
	// Устанавливаем fakeTTL (#2): оригинальный TTL (64 или 128) доходит до сервера.
	// fakeTTL должен быть достаточно мал (обычно 6) чтобы умереть до QUIC сервера.
	if fakeTTL > 0 && fakeTTL < 256 {
		pkt[8] = byte(fakeTTL)
	}

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

// fixUDPChecksum пересчитывает UDP checksum без аллокаций (#6).
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

	var sum uint32
	// Псевдозаголовок
	sum += uint32(packet[12])<<8 | uint32(packet[13])
	sum += uint32(packet[14])<<8 | uint32(packet[15])
	sum += uint32(packet[16])<<8 | uint32(packet[17])
	sum += uint32(packet[18])<<8 | uint32(packet[19])
	sum += uint32(17) // protocol UDP
	sum += uint32(udpLen)

	// UDP заголовок + данные
	udp := packet[udpOffset:]
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(udp[i])<<8 | uint32(udp[i+1])
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	cs := ^uint16(sum)

	if cs == 0 {
		cs = 0xFFFF
	}

	packet[udpOffset+6] = byte(cs >> 8)
	packet[udpOffset+7] = byte(cs)
}

// Вспомогательная функция
func getTCPSeq(pkt []byte) uint32 {
	ipLen := int(pkt[0]&0x0F) * 4
	return binary.BigEndian.Uint32(pkt[ipLen+4:])
}

// sendPacket реинжектирует пакет без модификаций (passthrough).
// Checksum offload биты не трогаем — Windows пересчитает checksum сама.
func (p *Pipeline) sendPacket(data []byte, addr []byte) bool {
	if len(data) < 20 {
		log.Printf("WARNING: Attempted to send packet too short (%d bytes)", len(data))
		return false
	}
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

// sendModifiedPacket отправляет fake/split/disorder пакет с ручным checksum.
// Вызывает SendModified — сбрасывает checksum offload биты в addr,
// иначе Windows перезапишет наш intentionally-recalculated/bad checksum своим.
func (p *Pipeline) sendModifiedPacket(data []byte, addr []byte) bool {
	if len(data) < 20 {
		log.Printf("WARNING: Attempted to send modified packet too short (%d bytes)", len(data))
		return false
	}
	if len(addr) == 0 {
		log.Printf("ERROR: addr is empty — skipping modified send")
		return false
	}
	if err := p.sender.SendModified(data, addr); err != nil {
		log.Printf("ERROR: Failed to send modified packet: %v", err)
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
		case result, ok := <-p.resultChan:
			if !ok {
				return
			}

			if p.strategyMgr != nil {
				success := len(result.ModifiedPackets) > 0 || result.SendOriginal

				strategyResult := &strategy.StrategyResult{
					StrategyID:   result.StrategyID,
					Success:      success,
					ResponseTime: 0,
					BytesSent:    len(result.ModifiedPackets) * 1500,
					PacketsSent:  len(result.ModifiedPackets),
					Timestamp:    time.Now(),
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
		src := net.IPv4(packet[12], packet[13], packet[14], packet[15])
		dst := net.IPv4(packet[16], packet[17], packet[18], packet[19])
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
	if ttl <= 0 {
		ttl = 6 // zapret default: достаточно до DPI, умирает до сервера (#BugTTL0)
	}
	packet[8] = byte(ttl)
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
