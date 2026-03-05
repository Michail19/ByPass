//go:build windows
// +build windows

package capture

import (
	"context"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// WinDivertHandle для работы с WinDivert
type WinDivertHandle uintptr

// WinDivert реализует захват через WinDivert для Windows
type WinDivert struct {
	handle   WinDivertHandle
	packets  chan Packet
	stopChan chan struct{}
	config   Config
	dll      *syscall.DLL
}

// NewWinDivert создает новый захватчик для Windows
func NewWinDivert(cfg Config) (*WinDivert, error) {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 65535
	}
	if cfg.MaxPacketLen <= 0 {
		cfg.MaxPacketLen = 65535
	}

	return &WinDivert{
		packets:  make(chan Packet, cfg.BufferSize),
		stopChan: make(chan struct{}),
		config:   cfg,
	}, nil
}

// Start запускает захват пакетов через WinDivert
func (w *WinDivert) Start(ctx context.Context) error {
	log.Printf("DEBUG: Initializing WinDivert...")

	// Проверяем наличие DLL
	if _, err := os.Stat("WinDivert.dll"); err != nil {
		log.Printf("WARNING: WinDivert.dll not found in current directory")
	}

	// Загружаем WinDivert DLL
	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		return fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}
	w.dll = dll
	log.Printf("DEBUG: WinDivert.dll loaded successfully")

	// Получаем функции
	openProc, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return fmt.Errorf("failed to find WinDivertOpen: %v", err)
	}

	// Создаем фильтр для захвата трафика
	filter := "tcp.DstPort == 80 or tcp.DstPort == 443"
	log.Printf("DEBUG: Using filter: %s", filter)

	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return fmt.Errorf("failed to create filter: %v", err)
	}

	// WinDivertOpen(filter, layer, priority, flags)
	handle, _, _ := openProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		0, // WINDIVERT_LAYER_NETWORK
		0, // priority
		0, // flags
	)

	if handle == 0 {
		return fmt.Errorf("failed to open WinDivert - check if running as Administrator")
	}
	w.handle = WinDivertHandle(handle)
	log.Printf("DEBUG: WinDivert opened successfully, handle=%v", handle)

	// Запускаем обработку
	go w.processPackets(ctx)

	log.Printf("WinDivert started on Windows")
	return nil
}

// Stop останавливает захват
func (w *WinDivert) Stop() error {
	close(w.stopChan)

	if w.handle != 0 && w.dll != nil {
		closeProc, err := w.dll.FindProc("WinDivertClose")
		if err == nil {
			closeProc.Call(uintptr(w.handle))
		}
	}

	close(w.packets)
	return nil
}

// Packets возвращает канал с пакетами
func (w *WinDivert) Packets() <-chan Packet {
	return w.packets
}

// processPackets обрабатывает входящие пакеты
func (w *WinDivert) processPackets(ctx context.Context) {
	// Получаем функции WinDivert
	recvProc, err := w.dll.FindProc("WinDivertRecv")
	if err != nil {
		log.Printf("Failed to find WinDivertRecv: %v", err)
		return
	}

	buf := make([]byte, w.config.MaxPacketLen)

	for {
		select {
		case <-w.stopChan:
			return
		case <-ctx.Done():
			return
		default:
			// WinDivertRecv(handle, packet, packetLen, &recvLen, &addr)
			var recvLen uint
			var addr [64]byte // WINDIVERT_ADDRESS

			ret, _, _ := recvProc.Call(
				uintptr(w.handle),
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(len(buf)),
				uintptr(unsafe.Pointer(&recvLen)),
				uintptr(unsafe.Pointer(&addr[0])),
			)

			if ret == 0 {
				// Ошибка или нет данных
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Создаем пакет
			packet := &Packet{
				ID:        uint32(time.Now().UnixNano()),
				Data:      make([]byte, recvLen),
				Length:    int(recvLen),
				Timestamp: time.Now().UnixNano(),
			}
			copy(packet.Data, buf[:recvLen])

			// Отправляем в канал
			select {
			case w.packets <- *packet:
				// Пакет отправлен успешно
			default:
				// Канал переполнен
				log.Printf("Packet channel full, dropping packet")
			}
		}
	}
}
