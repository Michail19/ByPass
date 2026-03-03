package sender

import (
	"errors"
	"time"
)

// Sender определяет интерфейс для отправки пакетов
type Sender interface {
	Send(packet []byte) error
	SendWithDelay(packet []byte, delay time.Duration) error
	SendBatch(packets [][]byte) error
	Close() error
}

// Config конфигурация отправителя
type Config struct {
	Interface   string        // сетевой интерфейс
	BufferSize  int           // размер буфера
	SendTimeout time.Duration // таймаут отправки
	BatchSize   int           // размер батча для групповой отправки
}

// PacketToSend пакет для отправки
type PacketToSend struct {
	Data      []byte
	Delay     time.Duration
	Timestamp time.Time
}

// SenderStats статистика отправителя
type SenderStats struct {
	PacketsSent   uint64
	PacketsFailed uint64
	BytesSent     uint64
	BatchesSent   uint64
}

// Общие ошибки
var (
	ErrInvalidPacket = errors.New("invalid packet")
	ErrSendTimeout   = errors.New("send timeout")
	ErrNotSupported  = errors.New("platform not supported")
)

// NewSender — это заглушка. Реальная реализация в platform-specific файлах.
// Она будет переопределена через build tags.
var NewSender = func(cfg Config) (Sender, error) {
	// Эта функция будет переопределена в платформозависимых файлах
	return nil, ErrNotSupported
}
