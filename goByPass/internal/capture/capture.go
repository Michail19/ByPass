package capture

import "context"

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
