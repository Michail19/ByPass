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

// Start запускает захват пакетов
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

	// Проверяем, что фильтр корректен
	filter := "tcp.DstPort == 443 or tcp.DstPort == 80"
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return fmt.Errorf("failed to create filter: %v", err)
	}

	// Пробуем открыть с разными флагами
	flags := []int{0, 1} // 0=normal, 1=sniff

	for _, flag := range flags {
		log.Printf("DEBUG: Trying to open WinDivert with flag=%d", flag)

		handle, _, _ := openProc.Call(
			uintptr(unsafe.Pointer(filterPtr)),
			0, // WINDIVERT_LAYER_NETWORK
			0, // priority
			uintptr(flag),
		)

		if handle != 0 {
			w.handle = WinDivertHandle(handle)
			log.Printf("DEBUG: WinDivert opened successfully with flag=%d, handle=%v", flag, handle)

			// Проверяем, что handle действительно работает
			testProc, err := dll.FindProc("WinDivertGetParam")
			if err == nil {
				var param uint
				ret, _, _ := testProc.Call(
					uintptr(handle),
					0, // WINDIVERT_PARAM_QUEUE_LEN
					uintptr(unsafe.Pointer(&param)),
				)
				if ret != 0 {
					log.Printf("DEBUG: WinDivert param test successful, queue_len=%d", param)
				}
			}

			go w.processPackets(ctx)
			log.Printf("WinDivert started on Windows with flag=%d", flag)
			return nil
		}

		lastErr := syscall.GetLastError()
		log.Printf("DEBUG: WinDivertOpen failed with flag=%d, lastError=%v", flag, lastErr)
	}

	return fmt.Errorf("failed to open WinDivert with any flags")
}

// GetHandle возвращает WinDivert handle
func (w *WinDivert) GetHandle() uintptr {
	if w == nil || w.handle == 0 {
		log.Printf("WARNING: WinDivert.GetHandle called with nil or zero handle")
		return 0
	}
	log.Printf("DEBUG: WinDivert.GetHandle returning: %v", uintptr(w.handle))
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
	recvProc, err := w.dll.FindProc("WinDivertRecv")
	if err != nil {
		log.Printf("Failed to find WinDivertRecv: %v", err)
		return
	}

	buf := make([]byte, w.config.MaxPacketLen)
	dropCount := 0

	for {
		select {
		case <-w.stopChan:
			return
		case <-ctx.Done():
			return
		default:
			var recvLen uint
			var addr [64]byte

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

			// Копируем адрес
			addrCopy := make([]byte, 64)
			copy(addrCopy, addr[:])

			dataCopy := make([]byte, recvLen)
			copy(dataCopy, buf[:recvLen])

			packet := Packet{
				ID:        uint32(time.Now().UnixNano()),
				Data:      dataCopy,
				Length:    int(recvLen),
				Timestamp: time.Now().UnixNano(),
				Addr:      addrCopy,
			}

			// Неблокирующая отправка с подсчетом дропов
			select {
			case w.packets <- packet:
				if dropCount > 0 {
					log.Printf("Recovered from drop, %d packets were dropped", dropCount)
					dropCount = 0
				}
			default:
				dropCount++
				if dropCount%100 == 0 {
					log.Printf("WARNING: Packet channel full, dropped %d packets so far", dropCount)
				}
			}
		}
	}
}
