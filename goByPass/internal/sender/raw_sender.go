package sender

import (
	"golang.org/x/net/ipv4"
	"net"
)

// Sender определяет интерфейс для отправки пакетов
type Sender interface {
	Send(packet []byte) error
	Close() error
}

// RawSender отправляет пакеты через raw socket
type RawSender struct {
	conn *ipv4.RawConn
}

func NewRawSender() (*RawSender, error) {
	// Создаем raw socket
	c, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	conn, err := ipv4.NewRawConn(c)
	if err != nil {
		c.Close()
		return nil, err
	}

	return &RawSender{conn: conn}, nil
}

func (s *RawSender) Send(packet []byte) error {
	// Парсим IP-заголовок
	header, err := ipv4.ParseHeader(packet)
	if err != nil {
		return err
	}

	// Отправляем пакет
	return s.conn.WriteTo(header, packet[header.Len:], nil)
}

func (s *RawSender) Close() error {
	return s.conn.Close()
}
