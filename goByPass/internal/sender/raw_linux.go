//go:build linux
// +build linux

package sender

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// RawSender отправляет пакеты через raw socket (Linux)
type RawSender struct {
	fd    int
	cfg   Config
	stats SenderStats
}

// init регистрирует фабричную функцию для Linux
func init() {
	// Переопределяем NewSender для Linux
	NewSender = newLinuxSender
}

// newLinuxSender создает новый отправитель для Linux
func newLinuxSender(cfg Config) (Sender, error) {
	// Создаем raw socket
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	// Включаем IP_HDRINCL (мы сами формируем заголовок)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %v", err)
	}

	// Устанавливаем таймаут отправки
	if cfg.SendTimeout > 0 {
		tv := unix.NsecToTimeval(cfg.SendTimeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set send timeout: %v", err)
		}
	}

	// Привязываемся к интерфейсу, если указан
	if cfg.Interface != "" {
		iface, err := net.InterfaceByName(cfg.Interface)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to get interface: %v", err)
		}

		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Index); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to bind to interface: %v", err)
		}
	}

	// Устанавливаем размер буфера
	if cfg.BufferSize > 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, cfg.BufferSize); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set send buffer: %v", err)
		}
	}

	return &RawSender{
		fd:  fd,
		cfg: cfg,
	}, nil
}

// Send отправляет один пакет
func (s *RawSender) Send(packet []byte) error {
	if len(packet) < 20 {
		s.stats.PacketsFailed++
		return ErrInvalidPacket
	}

	// Извлекаем destination IP из заголовка
	dstIP := net.IP(packet[16:20])

	// Создаем sockaddr для отправки
	var addr unix.SockaddrInet4
	copy(addr.Addr[:], dstIP.To4())

	// Отправляем пакет
	err := unix.Sendto(s.fd, packet, 0, &addr)
	if err != nil {
		s.stats.PacketsFailed++
		return fmt.Errorf("sendto failed: %v", err)
	}

	s.stats.PacketsSent++
	s.stats.BytesSent += uint64(len(packet))

	return nil
}

// SendWithDelay отправляет пакет с задержкой
func (s *RawSender) SendWithDelay(packet []byte, delay time.Duration) error {
	time.Sleep(delay)
	return s.Send(packet)
}

// SendBatch отправляет несколько пакетов
func (s *RawSender) SendBatch(packets [][]byte) error {
	for _, packet := range packets {
		if err := s.Send(packet); err != nil {
			return err
		}
	}
	s.stats.BatchesSent++
	return nil
}

// Close закрывает сокет
func (s *RawSender) Close() error {
	if s.fd >= 0 {
		return unix.Close(s.fd)
	}
	return nil
}

// GetStats возвращает статистику
func (s *RawSender) GetStats() SenderStats {
	return s.stats
}

// RawConn отправка через ipv4.RawConn (альтернативный метод)
type RawConn struct {
	conn *ipv4.RawConn
}

// NewRawConn создает новый RawConn
func NewRawConn() (*RawConn, error) {
	c, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	conn, err := ipv4.NewRawConn(c)
	if err != nil {
		c.Close()
		return nil, err
	}

	return &RawConn{conn: conn}, nil
}

// Send отправляет пакет через RawConn
func (r *RawConn) Send(packet []byte) error {
	header, err := ipv4.ParseHeader(packet)
	if err != nil {
		return err
	}

	return r.conn.WriteTo(header, packet[header.Len:], nil)
}
