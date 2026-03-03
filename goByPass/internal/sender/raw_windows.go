//go:build windows
// +build windows

package sender

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	_ "golang.org/x/sys/unix"
)

// Windows-specific константы
const (
	IPPROTO_RAW = 255
	IP_HDRINCL  = 2
	SOCK_RAW    = 3
)

// WinDivertHandle для работы с WinDivert
type WinDivertHandle uintptr

// RawSender отправляет пакеты через WinDivert (Windows)
type RawSender struct {
	handle WinDivertHandle
	cfg    Config
	stats  SenderStats
}

// init регистрирует фабричную функцию для Windows
func init() {
	// Переопределяем NewSender для Windows
	NewSender = newWindowsSender
}

// newWindowsSender создает новый отправитель для Windows
func newWindowsSender(cfg Config) (Sender, error) {
	// Пытаемся загрузить WinDivert DLL
	handle, err := openWinDivert()
	if err == nil {
		return &RawSender{
			handle: handle,
			cfg:    cfg,
		}, nil
	}

	// Если WinDivert не доступен, пробуем raw socket
	return newRawSocketSender(cfg)
}

// openWinDivert открывает WinDivert
func openWinDivert() (WinDivertHandle, error) {
	// Загружаем WinDivert DLL
	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}

	// Получаем функции
	openProc, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return 0, fmt.Errorf("failed to find WinDivertOpen: %v", err)
	}

	// Открываем WinDivert с фильтром
	filter := "tcp.DstPort == 443 or tcp.DstPort == 80"
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}

	// WinDivertOpen(filter, layer, priority, flags)
	handle, _, _ := openProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		0, // WINDIVERT_LAYER_NETWORK
		0, // priority
		0, // flags
	)

	if handle == 0 {
		return 0, fmt.Errorf("failed to open WinDivert")
	}

	return WinDivertHandle(handle), nil
}

// newRawSocketSender создает raw socket отправитель
func newRawSocketSender(cfg Config) (Sender, error) {
	// В Windows raw sockets требуют админских прав
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 0x1) // 0x1 - syscall.IPPROTO_ICMP
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	return &RawSocketSender{
		fd:  fd,
		cfg: cfg,
	}, nil
}

// RawSocketSender для raw socket в Windows
type RawSocketSender struct {
	fd    syscall.Handle
	cfg   Config
	stats SenderStats
}

// Send отправляет пакет через raw socket
func (s *RawSocketSender) Send(packet []byte) error {
	if len(packet) < 20 {
		s.stats.PacketsFailed++
		return ErrInvalidPacket
	}

	dstIP := net.IP(packet[16:20])

	var addr syscall.RawSockaddrInet4
	addr.Family = syscall.AF_INET
	copy(addr.Addr[:], dstIP.To4())

	sockaddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte(addr.Addr),
	}

	err := syscall.Sendto(s.fd, packet, 0, sockaddr)
	if err != nil {
		s.stats.PacketsFailed++
		return fmt.Errorf("sendto failed: %v", err)
	}

	s.stats.PacketsSent++
	s.stats.BytesSent += uint64(len(packet))

	return nil
}

// SendWithDelay отправляет с задержкой
func (s *RawSocketSender) SendWithDelay(packet []byte, delay time.Duration) error {
	time.Sleep(delay)
	return s.Send(packet)
}

// SendBatch отправляет несколько пакетов
func (s *RawSocketSender) SendBatch(packets [][]byte) error {
	for _, packet := range packets {
		if err := s.Send(packet); err != nil {
			return err
		}
	}
	s.stats.BatchesSent++
	return nil
}

// Close закрывает сокет
func (s *RawSocketSender) Close() error {
	if s.fd != 0 {
		return syscall.Close(s.fd)
	}
	return nil
}

// GetStats возвращает статистику
func (s *RawSocketSender) GetStats() SenderStats {
	return s.stats
}

// Send отправляет пакет через WinDivert
func (s *RawSender) Send(packet []byte) error {
	dll, _ := syscall.LoadDLL("WinDivert.dll")
	sendProc, _ := dll.FindProc("WinDivertSend")

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

// SendWithDelay отправляет с задержкой
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
