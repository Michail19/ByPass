package sender

import (
	"errors"
	"time"
)

// Sender определяет интерфейс для отправки пакетов
type Sender interface {
	Send(packet []byte, addr []byte) error // Теперь всегда с addr
	SendWithDelay(packet []byte, addr []byte, delay time.Duration) error
	SendBatch(packets [][]byte, addr []byte) error // addr для всего батча
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
var NewSender = func(cfg Config) (Sender, error) {
	// Эта функция будет переопределена в платформозависимых файлах
	return nil, ErrNotSupported
}

// NewSenderWithHandle создает отправитель с существующим handle (для WinDivert)
var NewSenderWithHandle = func(handle uintptr, cfg Config) (Sender, error) {
	return nil, ErrNotSupported
}
