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
	p.cancel()

	if err := p.capturer.Stop(); err != nil {
		log.Printf("Error stopping capturer: %v", err)
	}

	p.wg.Wait()

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
				case <-time.After(2 * time.Millisecond):
					p.updateStats(func(stats *PipelineStats) { stats.PacketsDropped++ })
					log.Printf("WARNING: Worker %d queue full, dropping handshake packet", workerIdx)
				}
			} else {
				select {
				case ch <- packet:
				case <-p.ctx.Done():
					return
				default:
					// data-пакеты дропаем немедленно — TCP retransmit восстановит.
					p.updateStats(func(stats *PipelineStats) { stats.PacketsDropped++ })
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
			//     корректно применится (#5).
			//   - SelectStrategy приоритет: testOverride (по hostname) → isGoogleIP (по IP) →
			//     bestForProtocol. Если hostname пуст — isGoogleIP всё равно сработает.
			strat := p.strategyMgr.SelectStrategy(dstIP.String(), flowHostname, 443, "udp")
			if strat != nil && strat.NeedsQUICFake() {
				// Inject fake QUIC Initial только для первых пакетов handshake (#5).
				// QUIC-соединение: 1-2 Initial пакета → handshake → тысячи data пакетов.
				// Без ограничения: 6 fake × тысячи пакетов = throughput collapse.
				flow.Mu.Lock()
				alreadyInjected := flow.QUICFakeInjected
				if !alreadyInjected {
					flow.QUICFakeInjected = true
				}
				flow.Mu.Unlock()

				if !alreadyInjected {
					repeats := strat.FakeQUICRepeats
					if repeats <= 0 {
						repeats = 6
					}
					// TTL для fake QUIC (#2): используем QUICttl если задан, иначе FakeTTL.
					// Без TTL ограничения fake пакет доходит до Google QUIC сервера (TTL=64/128),
					// Google может ответить Stateless Reset → connection retry → slow start.
					// Цель: пакет доходит до DPI (1-3 hop), умирает до сервера (~6-10 hop).
					fakeTTL := strat.QUICttl
					if fakeTTL <= 0 {
						fakeTTL = strat.FakeTTL
					}
					if fakeTTL <= 0 {
						fakeTTL = 10 // zapret default: TTL=6
					}
					for i := 0; i < repeats; i++ {
						fakePkt := buildFakeQUICPacket(pkt.Data, strat.FakeQUICFileData, fakeTTL)
						if fakePkt != nil {
							p.sendModifiedPacket(fakePkt, pkt.Addr)
							p.updateStats(func(stats *PipelineStats) { stats.PacketsModified++ })
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
				flow.DataPacketsModified = 0
				flow.Mu.Unlock()
			} else if info.Host != "" {
				flow.SetHostname(info.Host)
				flowHostname = info.Host // обновляем локальную копию
				flow.Mu.Lock()
				flow.IsAnalyzed = true
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
		flow.Mu.Lock()
		if !flow.IsAnalyzed {
			flow.DataPacketsModified++
			if flow.DataPacketsModified >= 4 {
				flow.IsAnalyzed = true
				flow.DataPacketsModified = 0
			}
		}
		flow.Mu.Unlock()
	}

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
	fresh := p.strategyMgr.SelectStrategy(
		dstIP.String(),
		flowHostname,
		int(dstPort),
		"tcp",
	)

	// 2. Если hostname ещё не известен, а в кэше уже есть non-passthrough — кэш важнее fresh passthrough
	preferCached := flowHostname == "" && cached != nil && cachedStratID > 1

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

		// Обновляем IP cache только когда hostname уже известен
		if flowHostname != "" && (strategyID != cachedStratID || cached == nil) {
			p.ipCache.PutByIP(dstIP, flowHostname, shouldBypass, strategyID)
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
		// Определить тип пакета (уже есть)
		ipHeaderLen := int(pkt.Data[0]&0x0F) * 4
		tcpOffset := ipHeaderLen

		if len(pkt.Data) < tcpOffset+14 {
			p.sendPacket(pkt.Data, pkt.Addr)
			return
		}

		flags := pkt.Data[tcpOffset+13]
		isSYN := (flags & 0x02) != 0
		isACK := (flags & 0x10) != 0
		tcpHeaderLen := int(pkt.Data[tcpOffset+12]>>4) * 4
		payloadOffset := tcpOffset + tcpHeaderLen
		isData := len(pkt.Data) > payloadOffset
		isClientHello := isData &&
			len(pkt.Data) >= payloadOffset+6 &&
			pkt.Data[payloadOffset] == 0x16

		// Для TLS-only syndata профилей (например, yt-syndata-2026) не применяем
		// SYN-data до тех пор, пока hostname/SNI ещё не известен.
		//
		// Идея:
		//   - bare SYN отправляем как есть;
		//   - первый ClientHello анализатор уже разберёт, выставит flowHostname;
		//   - после этого та же стратегия сможет примениться уже по hostname.
		//
		// Это защищает от слишком раннего fake SYN на bare-IP Google/YouTube flow.
		skipBareSynData := isSYN &&
			flowHostname == "" &&
			strats != nil &&
			strats.SynData &&
			strats.ApplyToTLS &&
			!strats.ApplyToHTTP &&
			!strats.AnyProtocol

		if skipBareSynData {
			log.Printf(
				"[PIPELINE] Skip bare-IP SYN-data for strategy %d (%s) ip=%s:%d; waiting for SNI/Host",
				strats.ID, strats.Name, dstIP.String(), dstPort,
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

			// Отправляем результат в менеджер стратегий для статистики
			if p.strategyMgr != nil {
				// BUG FIX: ранее len(result.ModifiedPackets)==0 считалось ошибкой,
				// но это нормально когда стратегия вернула только SendOriginal=true.
				// Такое ложное "failure" инвалидировало кэш без причины.
				// Теперь: неудача только если задержка избыточно велика (>1с).
				success := result.Delay <= 1000

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
		ttl = 10 // zapret default: достаточно до DPI, умирает до сервера (#BugTTL0)
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
