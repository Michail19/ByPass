//go:build windows
// +build windows

package sender

import (
	"fmt"
	_ "net"
	"syscall"
	"time"
	"unsafe"
)

// WinDivertHandle для работы с WinDivert
type WinDivertHandle uintptr

// RawSender отправляет пакеты через WinDivert (Windows)
type RawSender struct {
	handle WinDivertHandle
	cfg    Config
	stats  SenderStats
}

// NewSender создает новый отправитель для Windows
func NewSender(cfg Config) (Sender, error) {
	// Загружаем WinDivert DLL
	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		return nil, fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}

	// Получаем функции
	openProc, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return nil, fmt.Errorf("failed to find WinDivertOpen: %v", err)
	}

	// Открываем WinDivert с фильтром (например, "tcp.DstPort == 443 or tcp.DstPort == 80")
	filter := "tcp.DstPort == 443 or tcp.DstPort == 80"
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	// WinDivertOpen(filter, layer, priority, flags)
	handle, _, _ := openProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		0, // WINDIVERT_LAYER_NETWORK
		0, // priority
		0, // flags
	)

	if handle == 0 {
		return nil, fmt.Errorf("failed to open WinDivert")
	}

	return &RawSender{
		handle: WinDivertHandle(handle),
		cfg:    cfg,
	}, nil
}

// Send отправляет пакет через WinDivert
func (s *RawSender) Send(packet []byte) error {
	// Получаем функции WinDivert
	dll, _ := syscall.LoadDLL("WinDivert.dll")
	sendProc, _ := dll.FindProc("WinDivertSend")

	// WinDivertSend(handle, packet, packetLen, &sendLen, nil)
	var sendLen uint
	ret, _, _ := sendProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		0,
	)

	if ret == 0 {
		s.stats.PacketsFailed++
		return fmt.Errorf("WinDivertSend failed")
	}

	s.stats.PacketsSent++
	s.stats.BytesSent += uint64(sendLen)

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

// Close закрывает WinDivert
func (s *RawSender) Close() error {
	if s.handle != 0 {
		dll, _ := syscall.LoadDLL("WinDivert.dll")
		closeProc, _ := dll.FindProc("WinDivertClose")
		closeProc.Call(uintptr(s.handle))
	}
	return nil
}

// GetStats возвращает статистику
func (s *RawSender) GetStats() SenderStats {
	return s.stats
}

// Альтернативная реализация через syscall.RawConn
type RawConn struct {
	fd syscall.Handle
}

// NewRawConnWindows создает raw socket (ограничено в Windows)
func NewRawConnWindows() (*RawConn, error) {
	// В Windows raw sockets требуют административных привилегий
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	// Включаем IP_HDRINCL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return &RawConn{fd: fd}, nil
}
