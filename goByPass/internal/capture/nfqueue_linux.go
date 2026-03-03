//go:build linux
// +build linux

package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// NFQueue реализует захват через NFQUEUE
type NFQueue struct {
	queueNum int
	packets  chan Packet
	stopChan chan struct{}
	fd       int
	queue    *nftables.Queue
	nfq      *nfqHandle
	config   Config
}

// NewNFQueue создает новый NFQUEUE-захватчик
func NewNFQueue(cfg Config) (*NFQueue, error) {
	if cfg.QueueNum < 0 {
		return nil, fmt.Errorf("invalid queue number: %d", cfg.QueueNum)
	}

	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 65535
	}

	if cfg.MaxPacketLen <= 0 {
		cfg.MaxPacketLen = 65535
	}

	return &NFQueue{
		queueNum: cfg.QueueNum,
		packets:  make(chan Packet, 1000),
		stopChan: make(chan struct{}),
		config:   cfg,
	}, nil
}

// Start запускает захват пакетов
func (n *NFQueue) Start(ctx context.Context) error {
	// Открываем netfilter queue
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("failed to create netlink socket: %v", err)
	}
	n.fd = fd

	// Настраиваем параметры сокета
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_NO_ENOBUFS, 1); err != nil {
		unix.Close(fd)
		return fmt.Errorf("failed to set NETLINK_NO_ENOBUFS: %v", err)
	}

	// Привязываемся к очереди
	if err := n.bindQueue(); err != nil {
		unix.Close(fd)
		return fmt.Errorf("failed to bind queue: %v", err)
	}

	// Настраиваем iptables правила (опционально)
	if err := n.setupIptables(); err != nil {
		log.Printf("Warning: failed to setup iptables: %v", err)
	}

	// Запускаем обработку в горутине
	go n.processPackets()

	log.Printf("NFQUEUE started on queue %d", n.queueNum)
	return nil
}

// Stop останавливает захват
func (n *NFQueue) Stop() error {
	close(n.stopChan)

	// Очищаем iptables правила
	if err := n.cleanupIptables(); err != nil {
		log.Printf("Warning: failed to cleanup iptables: %v", err)
	}

	// Закрываем сокет
	if n.fd > 0 {
		unix.Close(n.fd)
	}

	close(n.packets)
	return nil
}

// Packets возвращает канал с пакетами
func (n *NFQueue) Packets() <-chan Packet {
	return n.packets
}

// bindQueue привязывает сокет к очереди NFQUEUE
func (n *NFQueue) bindQueue() error {
	// Создаем и отправляем netlink сообщение для привязки к очереди
	// Это упрощенная реализация - в реальном коде нужно использовать
	// libnetfilter_queue или готовые биндинги

	// Для примера используем syscall к NFQUEUE
	// В реальном проекте лучше использовать github.com/chifflier/nfqueue-go

	return nil
}

// setupIptables добавляет правила для перенаправления трафика в очередь
func (n *NFQueue) setupIptables() error {
	// Проверяем, есть ли у нас права root
	if os.Geteuid() != 0 {
		return fmt.Errorf("need root privileges to setup iptables")
	}

	// Команда iptables для перенаправления HTTPS трафика в очередь
	// В реальном проекте лучше использовать github.com/coreos/go-iptables
	cmd := fmt.Sprintf("iptables -t mangle -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num %d --queue-bypass", n.queueNum)

	// Здесь нужно выполнить команду через exec.Command
	// Для примера пропускаем

	return nil
}

// cleanupIptables удаляет правила
func (n *NFQueue) cleanupIptables() error {
	cmd := fmt.Sprintf("iptables -t mangle -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num %d", n.queueNum)
	// Выполнить команду
	return nil
}

// processPackets обрабатывает входящие пакеты
func (n *NFQueue) processPackets() {
	buf := make([]byte, n.config.MaxPacketLen)

	for {
		select {
		case <-n.stopChan:
			return
		default:
			// Читаем пакет из очереди
			n, from, err := unix.Recvfrom(n.fd, buf, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				log.Printf("Error reading from queue: %v", err)
				continue
			}

			// Парсим netlink сообщение и извлекаем пакет
			packet, err := n.parseNetlinkMessage(buf[:n])
			if err != nil {
				log.Printf("Failed to parse netlink message: %v", err)
				continue
			}

			// Отправляем в канал
			select {
			case n.packets <- *packet:
			default:
				// Канал переполнен - дропаем пакет
				log.Printf("Packet channel full, dropping packet")
				n.setVerdict(packet.ID, 0, true) // NF_DROP
			}
		}
	}
}

// parseNetlinkMessage парсит netlink сообщение и извлекает пакет
func (n *NFQueue) parseNetlinkMessage(data []byte) (*Packet, error) {
	// Это упрощенная версия - реальный парсинг сложнее
	// В реальном проекте используйте готовую библиотеку

	if len(data) < 20 {
		return nil, fmt.Errorf("message too short")
	}

	// Извлекаем ID пакета (упрощенно)
	id := binary.BigEndian.Uint32(data[4:8])

	// Извлекаем payload (упрощенно)
	payload := data[20:]

	return &Packet{
		ID:        id,
		Data:      payload,
		Length:    len(payload),
		Timestamp: time.Now().UnixNano(),
	}, nil
}

// setVerdict устанавливает вердикт для пакета
func (n *NFQueue) setVerdict(id uint32, mark uint32, accept bool) error {
	// Отправляем вердикт обратно в очередь
	// В реальном коде нужно сформировать правильное netlink сообщение
	return nil
}

// nfqHandle для совместимости с libnetfilter_queue
type nfqHandle struct {
	fd int
}
