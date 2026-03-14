package sender

import (
	"errors"
	"sync/atomic"
	"time"
)

// Sender определяет интерфейс для отправки пакетов
type Sender interface {
	// Send реинжектирует пакет без изменений (passthrough).
	// Checksum offload биты в addr оставляются как есть — Windows пересчитает checksum сама.
	Send(packet []byte, addr []byte) error

	// SendModified отправляет пакет с ручным checksum.
	// Сбрасывает checksum offload биты в addr (копии) перед отправкой — иначе
	// Windows перезапишет наш intentionally-bad/recalculated checksum своим.
	// Используется для fake, split, disorder пакетов.
	SendModified(packet []byte, addr []byte) error

	SendWithDelay(packet []byte, addr []byte, delay time.Duration) error
	SendBatch(packets [][]byte, addr []byte) error
	GetStats() SenderStatsSnapshot
	Close() error
}

// Config конфигурация отправителя
type Config struct {
	Interface   string
	BufferSize  int
	SendTimeout time.Duration
	BatchSize   int
}

// PacketToSend пакет для отправки
type PacketToSend struct {
	Data      []byte
	Delay     time.Duration
	Timestamp time.Time
}

// SenderStats статистика отправителя.
// Все поля обновляются через atomic — безопасно из нескольких горутин (#12).
type SenderStats struct {
	PacketsSent   atomic.Uint64
	PacketsFailed atomic.Uint64
	BytesSent     atomic.Uint64
	BatchesSent   atomic.Uint64
}

// Snapshot возвращает мгновенный снимок статистики (без гонок).
func (s *SenderStats) Snapshot() SenderStatsSnapshot {
	return SenderStatsSnapshot{
		PacketsSent:   s.PacketsSent.Load(),
		PacketsFailed: s.PacketsFailed.Load(),
		BytesSent:     s.BytesSent.Load(),
		BatchesSent:   s.BatchesSent.Load(),
	}
}

// SenderStatsSnapshot — иммутабельный снимок статистики для логирования/UI.
type SenderStatsSnapshot struct {
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
	ErrClosed        = errors.New("sender is closed")
)

// NewSender — заглушка, переопределяется в platform-specific файлах.
var NewSender = func(cfg Config) (Sender, error) {
	return nil, ErrNotSupported
}

// NewSenderWithHandle создаёт отправитель с существующим handle (для WinDivert)
var NewSenderWithHandle = func(handle uintptr, cfg Config) (Sender, error) {
	return nil, ErrNotSupported
}
