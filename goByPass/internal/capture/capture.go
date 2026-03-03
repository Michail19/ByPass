package capture

import (
	"context"
	"errors"
)

// Packet представляет перехваченный сетевой пакет
type Packet struct {
	ID        uint32
	Mark      uint32
	Data      []byte
	Length    int
	Interface string
	Timestamp int64
}

// Capturer определяет интерфейс для перехватчиков пакетов
type Capturer interface {
	Start(ctx context.Context) error
	Stop() error
	Packets() <-chan Packet
}

// PacketModifier определяет интерфейс для модификации пакетов
type PacketModifier interface {
	Modify(packet *Packet) ([]byte, bool) // возвращает модифицированные данные и флаг "отправлять ли оригинал"
}

// Общие ошибки
var (
	ErrNotSupported = errors.New("platform not supported")
	ErrQueueFull    = errors.New("queue is full")
	ErrNotStarted   = errors.New("capturer not started")
)

// Config содержит общую конфигурацию для захвата
type Config struct {
	QueueNum     int    // номер очереди NFQUEUE
	BufferSize   int    // размер буфера
	Interface    string // интерфейс для захвата (пустая строка = все)
	MaxPacketLen int    // максимальная длина пакета
}
