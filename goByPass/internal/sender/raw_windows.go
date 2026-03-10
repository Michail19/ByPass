//go:build windows
// +build windows

package sender

import (
	"encoding/binary"
	"fmt"
	"log"
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
	handle     WinDivertHandle
	cfg        Config
	stats      SenderStats
	dll        *syscall.DLL  // Сохранённая DLL
	sendProc   *syscall.Proc // Сохранённая процедура
	sendExProc *syscall.Proc // Для batch
	closeProc  *syscall.Proc // Для close
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
		return nil, fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}

	// Находим процедуры
	sendProc, err := dll.FindProc("WinDivertSend")
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("failed to find WinDivertSend: %v", err)
	}
	sendExProc, err := dll.FindProc("WinDivertSendEx")
	if err != nil {
		log.Printf("WinDivertSendEx not found, batch will use loop: %v", err)
		sendExProc = nil
	}
	closeProc, err := dll.FindProc("WinDivertClose")
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("failed to find WinDivertClose: %v", err)
	}

	// Открываем handle
	handle, err := openWinDivertWithDLL(dll)
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("failed to open WinDivert: %v", err)
	}

	log.Printf("WinDivert initialized with handle: %v", handle)
	return &RawSender{
		handle:     handle,
		cfg:        cfg,
		dll:        dll,
		sendProc:   sendProc,
		sendExProc: sendExProc,
		closeProc:  closeProc,
	}, nil
}

// openWinDivertWithDLL открывает WinDivert
func openWinDivertWithDLL(dll *syscall.DLL) (WinDivertHandle, error) {
	openProc, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return 0, fmt.Errorf("failed to find WinDivertOpen: %v", err)
	}
	// Фикс: outbound and !loopback + UDP для QUIC
	filter := "outbound and !loopback and (tcp.DstPort == 443 or tcp.DstPort == 80 or udp.DstPort == 443)"
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

	return WinDivertHandle(handle), nil
}

// Send отправляет пакет через WinDivert с addr
func (s *RawSender) Send(packet []byte, addr []byte) error {
	if len(packet) < 20 {
		s.stats.PacketsFailed++
		return fmt.Errorf("%w: packet too short: %d bytes", ErrInvalidPacket, len(packet))
	}

	// Подготавливаем addr
	if len(addr) < 64 {
		log.Printf("WARNING: Address too short (%d), padding to 64", len(addr))
		newAddr := make([]byte, 64)
		copy(newAddr, addr)
		addr = newAddr
	}

	var sendLen uint
	ret, _, callErr := s.sendProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)

	if ret == 0 {
		s.stats.PacketsFailed++
		return fmt.Errorf("WinDivertSend failed: %v", callErr)
	}

	if sendLen != uint(len(packet)) {
		log.Printf("WARNING: Sent %d bytes but expected %d", sendLen, len(packet))
	}

	s.stats.PacketsSent++
	s.stats.BytesSent += uint64(sendLen)
	return nil
}

// SendWithDelay отправляет с задержкой
func (s *RawSender) SendWithDelay(packet []byte, addr []byte, delay time.Duration) error {
	time.Sleep(delay)
	return s.Send(packet, addr)
}

// SendBatch отправляет несколько пакетов
func (s *RawSender) SendBatch(packets [][]byte, addr []byte) error {
	if s.sendExProc == nil {
		// Fallback loop
		for _, pkt := range packets {
			if err := s.Send(pkt, addr); err != nil {
				return err
			}
		}
		s.stats.BatchesSent++
		return nil
	}

	// Native batch
	ptrs := make([]uintptr, len(packets))
	lens := make([]uint, len(packets))
	for i, pkt := range packets {
		ptrs[i] = uintptr(unsafe.Pointer(&pkt[0]))
		lens[i] = uint(len(pkt))
	}

	ret, _, err := s.sendExProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&ptrs[0])),
		uintptr(unsafe.Pointer(&lens[0])),
		uintptr(len(packets)),
	)
	if ret == 0 {
		return fmt.Errorf("WinDivertSendEx failed: %v", err)
	}
	s.stats.PacketsSent += uint64(len(packets))
	s.stats.BatchesSent++
	return nil
}

// Close закрывает WinDivert
func (s *RawSender) Close() error {
	if s.handle != 0 {
		ret, _, _ := s.closeProc.Call(uintptr(s.handle))
		if ret == 0 {
			return fmt.Errorf("failed to close WinDivert handle")
		}
		s.handle = 0
	}

	if s.dll != nil {
		s.dll.Release()
		s.dll = nil
	}

	s.sendProc = nil
	s.sendExProc = nil
	s.closeProc = nil

	return nil
}

// GetStats возвращает статистику
func (s *RawSender) GetStats() SenderStats {
	return s.stats
}

// newWindowsSenderWithHandle создает с handle
func newWindowsSenderWithHandle(handle uintptr, cfg Config) (Sender, error) {
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

	sendExProc, err := dll.FindProc("WinDivertSendEx")
	if err != nil {
		log.Printf("WinDivertSendEx not found: %v", err)
		sendExProc = nil
	}

	closeProc, err := dll.FindProc("WinDivertClose")
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("failed to find WinDivertClose: %v", err)
	}

	return &RawSender{
		handle:     WinDivertHandle(handle),
		cfg:        cfg,
		dll:        dll,
		sendProc:   sendProc,
		sendExProc: sendExProc,
		closeProc:  closeProc,
	}, nil
}

// recalculateIPChecksum пересчитывает IP checksum
func recalculateIPChecksum(packet []byte) {
	if len(packet) < 20 {
		return
	}
	packet[10] = 0
	packet[11] = 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(packet[10:12], checksum)
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
	for sum>>16 > 0 {
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

	packet[tcpOffset+16] = 0
	packet[tcpOffset+17] = 0

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], packet[12:16]) // Source IP
	copy(pseudo[4:8], packet[16:20]) // Dest IP

	pseudo[9] = 6 // Protocol TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-tcpOffset))

	tcpData := packet[tcpOffset:]
	fullData := append(pseudo, tcpData...)

	checksum := calculateChecksum(fullData)
	packet[tcpOffset+16] = byte(checksum >> 8)
	packet[tcpOffset+17] = byte(checksum & 0xFF)
}
