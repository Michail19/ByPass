//go:build windows
// +build windows

package sender

import (
	_ "encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"
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
	handle   WinDivertHandle
	cfg      Config
	stats    SenderStats
	dll      *syscall.DLL  // Сохраняем DLL
	sendProc *syscall.Proc // Сохраняем процедуру
}

// RawSocketSender для raw socket в Windows
type RawSocketSender struct {
	fd    syscall.Handle
	cfg   Config
	stats SenderStats
}

// init регистрирует фабричную функцию для Windows
func init() {
	// Переопределяем NewSender для Windows
	NewSender = newWindowsSender
	NewSenderWithHandle = newWindowsSenderWithHandle
}

// newWindowsSender создает новый отправитель для Windows
func newWindowsSender(cfg Config) (Sender, error) {
	// Загружаем DLL один раз
	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		log.Printf("WinDivert.dll not found, falling back to raw socket: %v", err)
		return newRawSocketSender(cfg)
	}

	sendProc, err := dll.FindProc("WinDivertSend")
	if err != nil {
		dll.Release()
		log.Printf("WinDivertSend not found, falling back to raw socket: %v", err)
		return newRawSocketSender(cfg)
	}

	handle, err := openWinDivertWithDLL(dll)
	if err != nil {
		dll.Release()
		log.Printf("Failed to open WinDivert, falling back to raw socket: %v", err)
		return newRawSocketSender(cfg)
	}

	log.Printf("WinDivert initialized successfully with handle: %v", handle)
	return &RawSender{
		handle:   handle,
		cfg:      cfg,
		dll:      dll,
		sendProc: sendProc,
	}, nil
}

// openWinDivertWithDLL открывает WinDivert с использованием загруженной DLL
func openWinDivertWithDLL(dll *syscall.DLL) (WinDivertHandle, error) {
	openProc, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return 0, fmt.Errorf("failed to find WinDivertOpen: %v", err)
	}

	// Открываем WinDivert с фильтром для всех пакетов на 80/443 портах
	filter := "tcp.DstPort == 443 or tcp.DstPort == 80 or tcp.SrcPort == 443 or tcp.SrcPort == 80"
	log.Printf("DEBUG: Opening WinDivert with filter: %s", filter)

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

	log.Printf("DEBUG: WinDivert opened successfully, handle=%v", handle)
	return WinDivertHandle(handle), nil
}

// openWinDivert (legacy) оставлен для обратной совместимости
func openWinDivert() (WinDivertHandle, error) {
	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}
	defer dll.Release()
	return openWinDivertWithDLL(dll)
}

// newRawSocketSender создает raw socket отправитель
func newRawSocketSender(cfg Config) (Sender, error) {
	// Для raw socket используем IPPROTO_RAW
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 0x1)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	// Включаем IP_HDRINCL (мы сами формируем заголовок)
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_HDRINCL, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %v", err)
	}

	log.Printf("Raw socket created successfully, fd=%v", fd)
	return &RawSocketSender{
		fd:  fd,
		cfg: cfg,
	}, nil
}

// Send отправляет пакет через raw socket
func (s *RawSocketSender) Send(packet []byte) error {
	if len(packet) < 20 {
		s.stats.PacketsFailed++
		return fmt.Errorf("%w: packet too short: %d bytes", ErrInvalidPacket, len(packet))
	}

	// Проверяем IP-заголовок
	version := packet[0] >> 4
	if version != 4 {
		log.Printf("WARNING: Non-IPv4 packet (version=%d) via raw socket", version)
	}

	// Получаем IP назначения из пакета
	dstIP := net.IP(packet[16:20])

	// Создаем sockaddr для отправки
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
		err := syscall.Close(s.fd)
		s.fd = 0
		return err
	}
	return nil
}

// GetStats возвращает статистику
func (s *RawSocketSender) GetStats() SenderStats {
	return s.stats
}

// Send отправляет пакет через WinDivert с проверкой
func (s *RawSender) Send(packet []byte) error {
	if len(packet) < 20 {
		s.stats.PacketsFailed++
		return fmt.Errorf("%w: packet too short: %d bytes", ErrInvalidPacket, len(packet))
	}

	// Проверяем IP-заголовок
	version := packet[0] >> 4
	if version != 4 {
		log.Printf("WARNING: Non-IPv4 packet (version=%d) via WinDivert", version)
	}

	var sendLen uint
	var addr [64]byte // Адресная структура WinDivert (может быть пустой для отправки)

	// Используем сохраненную процедуру
	ret, _, _ := s.sendProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)

	if ret == 0 {
		lastErr := syscall.GetLastError()
		s.stats.PacketsFailed++
		return fmt.Errorf("WinDivertSend failed: %v", lastErr)
	}

	// Проверяем, что все данные отправлены
	if sendLen != uint(len(packet)) {
		log.Printf("WARNING: WinDivert sent %d bytes but expected %d", sendLen, len(packet))
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

// Close закрывает WinDivert и освобождает ресурсы
func (s *RawSender) Close() error {
	var lastErr error

	if s.handle != 0 {
		closeProc, err := s.dll.FindProc("WinDivertClose")
		if err == nil {
			ret, _, _ := closeProc.Call(uintptr(s.handle))
			if ret == 0 {
				lastErr = fmt.Errorf("failed to close WinDivert handle")
			}
			s.handle = 0
		} else {
			lastErr = fmt.Errorf("failed to find WinDivertClose: %v", err)
		}
	}

	if s.dll != nil {
		s.dll.Release()
		s.dll = nil
	}

	s.sendProc = nil
	return lastErr
}

// GetStats возвращает статистику
func (s *RawSender) GetStats() SenderStats {
	return s.stats
}

// newWindowsSenderWithHandle создает отправитель с существующим handle
func newWindowsSenderWithHandle(handle uintptr, cfg Config) (Sender, error) {
	// Загружаем DLL для отправки
	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		return nil, fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}

	sendProc, err := dll.FindProc("WinDivertSend")
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("failed to find WinDivertSend: %v", err)
	}

	log.Printf("WinDivert sender created with shared handle: %v", handle)
	return &RawSender{
		handle:   WinDivertHandle(handle),
		cfg:      cfg,
		dll:      dll,
		sendProc: sendProc,
	}, nil
}
