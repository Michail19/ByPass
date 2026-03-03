package packetflow

import (
	"capture"
	"conntrack"
	"context"
	"modifier"
	"sender"
	"sync"
)

// Pipeline связывает все компоненты
type Pipeline struct {
	capturer  capture.Capturer
	conntrack *conntrack.Manager
	modifier  *modifier.PacketModifier
	sender    sender.Sender

	workers    int
	packetChan chan capture.Packet
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewPipeline(
	capturer capture.Capturer,
	conntrack *conntrack.Manager,
	modifier *modifier.PacketModifier,
	sender sender.Sender,
	workers int,
) *Pipeline {
	return &Pipeline{
		capturer:   capturer,
		conntrack:  conntrack,
		modifier:   modifier,
		sender:     sender,
		workers:    workers,
		packetChan: make(chan capture.Packet, 1000),
	}
}

// Start запускает обработку пакетов
func (p *Pipeline) Start() error {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Запускаем захват пакетов
	if err := p.capturer.Start(p.ctx); err != nil {
		return err
	}

	// Запускаем воркеров
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}

	// Передаем пакеты из капчера в канал
	go func() {
		for packet := range p.capturer.Packets() {
			select {
			case p.packetChan <- packet:
			case <-p.ctx.Done():
				return
			}
		}
	}()

	return nil
}

// worker обрабатывает пакеты
func (p *Pipeline) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case packet := <-p.packetChan:
			p.processPacket(&packet)
		case <-p.ctx.Done():
			return
		}
	}
}

// processPacket обрабатывает один пакет
func (p *Pipeline) processPacket(pkt *capture.Packet) {
	// Получаем или создаем поток
	flow := p.conntrack.GetOrCreate(
		extractSrcIP(pkt.Data),
		extractDstIP(pkt.Data),
		extractSrcPort(pkt.Data),
		extractDstPort(pkt.Data),
		extractProtocol(pkt.Data),
	)

	// Модифицируем пакет
	result := p.modifier.ModifyPacket(pkt.Data, flow)

	// Отправляем модифицированные пакеты
	for _, modifiedPkt := range result.ModifiedPackets {
		p.sender.Send(modifiedPkt)
	}

	// Если нужно, отправляем оригинал
	if result.SendOriginal {
		p.sender.Send(pkt.Data)
	}
}
