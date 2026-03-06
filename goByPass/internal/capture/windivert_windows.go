//go:build windows
// +build windows

package capture

import (
	"context"
	"fmt"
	"log"
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
	recvProc *syscall.Proc
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

	// Загружаем DLL один раз
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

	// Ловим пакеты в обе стороны
	filter := "tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 80 or tcp.SrcPort == 443"
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
		return fmt.Errorf("failed to open WinDivert")
	}
	w.handle = WinDivertHandle(handle)
	log.Printf("DEBUG: WinDivert opened successfully, handle=%v", handle)

	// Сохраняем процедуру для recv
	recvProc, err := dll.FindProc("WinDivertRecv")
	if err != nil {
		return fmt.Errorf("failed to find WinDivertRecv: %v", err)
	}
	w.recvProc = recvProc

	go w.processPackets(ctx)
	log.Printf("WinDivert started")
	return nil
}

// GetHandle возвращает WinDivert handle
func (w *WinDivert) GetHandle() uintptr {
	return uintptr(w.handle)
}

// Stop останавливает захват
func (w *WinDivert) Stop() error {
	close(w.stopChan)

	if w.handle != 0 && w.dll != nil {
		closeProc, _ := w.dll.FindProc("WinDivertClose")
		closeProc.Call(uintptr(w.handle))
		w.dll.Release()
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
			var addr [64]byte

			ret, _, _ := w.recvProc.Call(
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

			addrCopy := make([]byte, 64)
			copy(addrCopy, addr[:])

			packet := Packet{
				ID:        uint32(time.Now().UnixNano()),
				Data:      make([]byte, recvLen),
				Length:    int(recvLen),
				Timestamp: time.Now().UnixNano(),
				Addr:      addrCopy,
			}
			copy(packet.Data, buf[:recvLen])

			// Отправляем в канал
			select {
			case w.packets <- packet:
			default:
				log.Printf("Packet channel full")
			}
		}
	}
}
