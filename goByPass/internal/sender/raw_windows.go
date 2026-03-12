//go:build windows
// +build windows

package sender

import (
	"encoding/binary"
	"fmt"
	"log"
	"sync"
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

var (
	winDivertDLL *syscall.DLL
	once         sync.Once
)

// WinDivertHandle для работы с WinDivert
type WinDivertHandle uintptr

// RawSender отправляет пакеты через WinDivert (Windows)
type RawSender struct {
	handle    WinDivertHandle
	cfg       Config
	stats     SenderStats
	dll       *syscall.DLL
	sendProc  *syscall.Proc
	closeProc *syscall.Proc
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
		handle:    handle,
		cfg:       cfg,
		dll:       dll,
		sendProc:  sendProc,
		closeProc: closeProc,
	}, nil
}

// openWinDivertWithDLL открывает WinDivert
func openWinDivertWithDLL(dll *syscall.DLL) (WinDivertHandle, error) {
	openProc, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		return 0, fmt.Errorf("failed to find WinDivertOpen: %v", err)
	}
	// Перехватываем TCP 443/80 и UDP 443 (QUIC).
	// UDP 443 нужен для инжекции fake QUIC Initial перед реальным пакетом.
	// Реальный QUIC-пакет реинжектируется как есть — только fake-пакеты создаются из .bin.
	// WinDivert ожидает полный пакет (IP+UDP+payload) — fake строится с нуля в pipeline.
	filter := "outbound and !loopback and (tcp.DstPort == 443 or tcp.DstPort == 80 or (udp.DstPort == 443))"
	log.Printf("DEBUG: Opening WinDivert with filter: %s", filter)

	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}

	// WinDivertOpen(filter, layer, priority, flags)
	handle, _, err := openProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		0, // WINDIVERT_LAYER_NETWORK
		0, // priority
		0, // flags
	)

	if handle == 0 {
		return 0, fmt.Errorf("WinDivertOpen failed: %v", err)
	}

	return WinDivertHandle(handle), nil
}

// winDivertAddrClearChecksumFlags сбрасывает checksum-offload биты в WINDIVERT_ADDRESS.
//
// WINDIVERT_ADDRESS layout (WinDivert 2.x):
//
//	[0..7]  Timestamp (INT64)
//	[8..11] Flags (UINT32 bitfield):
//	          bits 0-7:  Layer
//	          bits 8-15: Event
//	          bit 16: Sniffed
//	          bit 17: Outbound
//	          bit 18: Loopback
//	          bit 19: Impostor
//	          bit 20: IPv6
//	          bit 21: IPChecksum   ← нужно сбросить для модифицированных пакетов
//	          bit 22: TCPChecksum  ← нужно сбросить для модифицированных пакетов
//	          bit 23: UDPChecksum  ← нужно сбросить для модифицированных пакетов
//
// Если offload-флаги выставлены, Windows пересчитает checksum сама и перезапишет
// наш вручную посчитанный — в результате DPI увидит правильный checksum.
// Для modified пакетов (fake/split/disorder) мы хотим именно наш checksum.
//
// Для passthrough пакетов НЕ вызываем — пусть offload работает как обычно.
func winDivertAddrClearChecksumFlags(addr []byte) {
	if len(addr) < 11 {
		return
	}
	// byte 10 содержит bits 16-23; IPChecksum=bit5, TCPChecksum=bit6, UDPChecksum=bit7
	addr[10] &^= 0xE0 // сбросить bits 5,6,7 байта 10 = bits 21,22,23 слова
}

// Send отправляет пакет через WinDivert с addr
func (s *RawSender) Send(packet []byte, addr []byte) error {
	return s.sendInternal(packet, addr, false)
}

// SendModified отправляет модифицированный пакет — сбрасывает checksum-offload флаги (#2).
// Используется для fake/split/disorder пакетов где checksum уже пересчитан вручную.
func (s *RawSender) SendModified(packet []byte, addr []byte) error {
	return s.sendInternal(packet, addr, true)
}

func (s *RawSender) sendInternal(packet []byte, addr []byte, clearChecksumFlags bool) error {
	if len(packet) < 20 {
		s.stats.PacketsFailed.Add(1)
		return fmt.Errorf("%w: packet too short: %d bytes", ErrInvalidPacket, len(packet))
	}
	if len(addr) < 32 {
		s.stats.PacketsFailed.Add(1)
		return fmt.Errorf("addr is empty: WinDivertSend requires original WINDIVERT_ADDRESS from WinDivertRecv")
	}

	// Для модифицированных пакетов: сбросить offload флаги в копии addr.
	// Оригинальный addr не трогаем — он может понадобиться для последующих sendPacket.
	sendAddr := addr
	if clearChecksumFlags && len(addr) >= 11 {
		addrCopy := make([]byte, len(addr))
		copy(addrCopy, addr)
		winDivertAddrClearChecksumFlags(addrCopy)
		sendAddr = addrCopy
	}

	var sendLen uint
	ret, _, callErr := s.sendProc.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&sendAddr[0])),
	)

	if ret == 0 {
		s.stats.PacketsFailed.Add(1)
		return fmt.Errorf("WinDivertSend failed: %v", callErr)
	}

	if sendLen != uint(len(packet)) {
		log.Printf("WARNING: Sent %d bytes but expected %d", sendLen, len(packet))
	}

	s.stats.PacketsSent.Add(1)
	s.stats.BytesSent.Add(uint64(sendLen))
	return nil
}

// SendWithDelay отправляет с задержкой
func (s *RawSender) SendWithDelay(packet []byte, addr []byte, delay time.Duration) error {
	time.AfterFunc(delay, func() {
		s.Send(packet, addr)
	})
	return nil
}

// SendBatch отправляет несколько пакетов последовательно.
//
// WinDivertSendEx НЕ поддерживает batch в виде массива буферов.
// Его настоящая сигнатура идентична WinDivertSend — это просто версия с флагами.
// Батч-отправка через один syscall в WinDivert невозможна (#3).
// Используем цикл — overhead минимален, пакеты уходят без лишних аллокаций.
func (s *RawSender) SendBatch(packets [][]byte, addr []byte) error {
	for _, pkt := range packets {
		if err := s.Send(pkt, addr); err != nil {
			return err
		}
	}
	s.stats.BatchesSent.Add(1)
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
	s.closeProc = nil

	return nil
}

// GetStats возвращает иммутабельный снимок статистики.
func (s *RawSender) GetStats() SenderStatsSnapshot {
	return s.stats.Snapshot()
}

// newWindowsSenderWithHandle создает с handle
func newWindowsSenderWithHandle(handle uintptr, cfg Config) (Sender, error) {
	if handle == 0 {
		return nil, fmt.Errorf("invalid handle (0)")
	}

	// Загружаем DLL для отправки
	once.Do(func() {
		winDivertDLL, err = syscall.LoadDLL("WinDivert.dll")
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load WinDivert.dll: %v", err)
	}

	sendProc, err := dll.FindProc("WinDivertSend")
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("failed to find WinDivertSend: %v", err)
	}

	closeProc, err := dll.FindProc("WinDivertClose")
	if err != nil {
		dll.Release()
		return nil, fmt.Errorf("failed to find WinDivertClose: %v", err)
	}

	return &RawSender{
		handle:    WinDivertHandle(handle),
		cfg:       cfg,
		dll:       dll,
		sendProc:  sendProc,
		closeProc: closeProc,
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
	ihl := int(packet[0]&0x0F) * 4
	for i := 0; i < ihl; i += 2 {
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

// fixUDPChecksum пересчитывает UDP контрольную сумму.
// Необходимо вызывать после любого изменения IP TTL или UDP payload для UDP пакетов,
// иначе QUIC-сервер дропнет пакет с invalid checksum.
func fixUDPChecksum(packet []byte) {
	if len(packet) < 28 {
		return
	}
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	if len(packet) < ipHeaderLen+8 {
		return
	}
	udpOffset := ipHeaderLen

	// Обнуляем checksum
	packet[udpOffset+6] = 0
	packet[udpOffset+7] = 0

	udpLen := len(packet) - udpOffset
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], packet[12:16]) // Source IP
	copy(pseudo[4:8], packet[16:20]) // Dest IP
	pseudo[9] = 17                   // Protocol UDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))

	udpData := packet[udpOffset:]
	fullData := make([]byte, 12+len(udpData))
	copy(fullData, pseudo)
	copy(fullData[12:], udpData)

	checksum := calculateChecksum(fullData)
	packet[udpOffset+6] = byte(checksum >> 8)
	packet[udpOffset+7] = byte(checksum & 0xFF)
}
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
	//fullData := append(pseudo, tcpData...)

	full := make([]byte, 12+len(tcpData))
	copy(full, pseudo)
	copy(full[12:], tcpData)

	checksum := calculateChecksum(full)
	packet[tcpOffset+16] = byte(checksum >> 8)
	packet[tcpOffset+17] = byte(checksum & 0xFF)
}
