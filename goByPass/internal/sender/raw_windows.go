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

// Send отправляет пакет через WinDivert с улучшенной диагностикой
func (s *RawSender) Send(packet []byte) error {
	if len(packet) < 20 {
		s.stats.PacketsFailed++
		log.Printf("ERROR: Packet too short: %d bytes", len(packet))
		return fmt.Errorf("packet too short: %d bytes", len(packet))
	}

	// Детальный анализ пакета
	version := packet[0] >> 4
	ihl := packet[0] & 0x0F
	totalLen := int(packet[2])<<8 | int(packet[3])
	protocol := packet[9]
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	log.Printf("DEBUG: Packet details - Version:%d IHL:%d TotalLen:%d Protocol:%d Src:%s Dst:%s",
		version, ihl, totalLen, protocol, srcIP, dstIP)

	if totalLen != len(packet) {
		log.Printf("WARNING: Total length mismatch: header=%d, actual=%d", totalLen, len(packet))
	}

	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		s.stats.PacketsFailed++
		return fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}
	defer dll.Release()

	sendProc, err := dll.FindProc("WinDivertSend")
	if err != nil {
		s.stats.PacketsFailed++
		return fmt.Errorf("failed to find WinDivertSend: %v", err)
	}

	var sendLen uint
	var addr [64]byte

	// Очищаем последнюю ошибку перед вызовом
	//syscall.SetLastError(0)

	log.Printf("DEBUG: Calling WinDivertSend with handle=%v, packetLen=%d", s.handle, len(packet))

	ret, _, callErr := sendProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)

	// Получаем последнюю ошибку Windows
	lastErr := syscall.GetLastError()

	if ret == 0 {
		errMsg := "unknown error"
		if callErr != nil {
			errMsg = callErr.Error()
			log.Printf(errMsg)
		}
		log.Printf("ERROR: WinDivertSend failed - ret=0, callErr=%v, lastError=%v", callErr, lastErr)
		log.Printf("ERROR: Failed packet - length=%d, protocol=%d, dst=%s", len(packet), protocol, dstIP)
		s.stats.PacketsFailed++
		return fmt.Errorf("WinDivertSend failed: %v (lastError: %v)", callErr, lastErr)
	}

	// Проверяем, что все данные отправлены
	if sendLen != uint(len(packet)) {
		log.Printf("WARNING: Sent %d bytes but expected %d", sendLen, len(packet))
	}

	log.Printf("DEBUG: Successfully sent %d bytes via WinDivert", sendLen)
	s.stats.PacketsSent++
	s.stats.BytesSent += uint64(sendLen)

	return nil
}

// SendWithAddr отправляет пакет с адресом
func (s *RawSender) SendWithAddr(packet []byte, addr []byte) error {
	// Проверяем handle
	if s.handle == 0 {
		return fmt.Errorf("invalid sender handle (0)")
	}

	log.Printf("DEBUG: SendWithAddr using handle=%v, packetLen=%d, addrLen=%d",
		s.handle, len(packet), len(addr))

	if len(packet) < 20 {
		return fmt.Errorf("packet too short: %d bytes", len(packet))
	}

	// Убеждаемся, что адрес имеет правильный размер
	if len(addr) < 64 {
		log.Printf("WARNING: Address too short (%d), padding to 64", len(addr))
		newAddr := make([]byte, 64)
		copy(newAddr, addr)
		addr = newAddr
	}

	// Логируем первые несколько байт адреса для отладки
	log.Printf("DEBUG: Address first 16 bytes: % x", addr[:16])

	var sendLen uint
	ret, _, _ := s.sendProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)

	if ret == 0 {
		lastErr := syscall.GetLastError()
		log.Printf("ERROR: WinDivertSend failed - handle=%v, len=%d, lastErr=%v",
			s.handle, len(packet), lastErr)
		s.stats.PacketsFailed++
		return fmt.Errorf("WinDivertSend failed: %v", lastErr)
	}

	if sendLen != uint(len(packet)) {
		log.Printf("WARNING: Sent %d bytes but expected %d", sendLen, len(packet))
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
	log.Printf("DEBUG: Creating sender with handle: %v", handle)

	if handle == 0 {
		return nil, fmt.Errorf("invalid handle (0)")
	}

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

// calculateChecksum вычисляет контрольную сумму для TCP/UDP
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// fixTCPChecksum пересчитывает TCP контрольную сумму
func fixTCPChecksum(packet []byte) {
	if len(packet) < 40 {
		return
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	tcpOffset := int(ipHeaderLen)

	if len(packet) < tcpOffset+20 {
		return
	}

	// Обнуляем текущую контрольную сумму
	packet[tcpOffset+16] = 0
	packet[tcpOffset+17] = 0

	// Создаем псевдо-заголовок для TCP
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], packet[12:16])                // Source IP
	copy(pseudo[4:8], packet[16:20])                // Dest IP
	pseudo[8] = 0                                   // Zero
	pseudo[9] = 6                                   // Protocol TCP
	pseudo[10] = byte(len(packet)-tcpOffset) >> 8   // TCP length high
	pseudo[11] = byte(len(packet)-tcpOffset) & 0xFF // TCP length low

	// Вычисляем сумму для псевдо-заголовка + TCP заголовок + данные
	tcpData := packet[tcpOffset:]
	fullData := append(pseudo, tcpData...)

	checksum := calculateChecksum(fullData)
	packet[tcpOffset+16] = byte(checksum >> 8)
	packet[tcpOffset+17] = byte(checksum & 0xFF)
}
