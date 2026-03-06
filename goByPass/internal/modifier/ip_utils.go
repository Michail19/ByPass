package modifier

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ExtractIPs извлекает source и destination IP из пакета
func ExtractIPs(packet []byte) (srcIP, dstIP net.IP, err error) {
	if len(packet) < 20 {
		return nil, nil, nil
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		return extractIPv4(packet)
	case 6:
		return extractIPv6(packet)
	default:
		return nil, nil, nil
	}
}

func extractIPv4(packet []byte) (srcIP, dstIP net.IP, err error) {
	if len(packet) < 20 {
		return nil, nil, nil
	}

	srcIP = net.IP(packet[12:16])
	dstIP = net.IP(packet[16:20])
	return srcIP, dstIP, nil
}

func extractIPv6(packet []byte) (srcIP, dstIP net.IP, err error) {
	if len(packet) < 40 {
		return nil, nil, nil
	}

	srcIP = net.IP(packet[8:24])
	dstIP = net.IP(packet[24:40])
	return srcIP, dstIP, nil
}

// ExtractPorts извлекает source и destination порты только для TCP/UDP
func ExtractPorts(packet []byte) (srcPort, dstPort uint16, protocol uint8, err error) {
	if len(packet) < 20 {
		return 0, 0, 0, fmt.Errorf("packet too short")
	}

	protocol = packet[9]

	// Только для TCP (6) и UDP (17)
	if protocol != 6 && protocol != 17 {
		return 0, 0, protocol, nil
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	if len(packet) < int(ipHeaderLen)+4 {
		return 0, 0, protocol, fmt.Errorf("packet too short for transport header")
	}

	transportOffset := int(ipHeaderLen)
	srcPort = binary.BigEndian.Uint16(packet[transportOffset:])
	dstPort = binary.BigEndian.Uint16(packet[transportOffset+2:])

	return srcPort, dstPort, protocol, nil
}

// CalculateTCPChecksum вычисляет контрольную сумму TCP (с псевдозаголовком)
func CalculateTCPChecksum(packet []byte) uint16 {
	if len(packet) < 40 { // IP(20) + TCP(20) минимум
		return 0
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpLen := len(packet) - ipHeaderLen

	// Создаем псевдозаголовок IPv4 (12 байт)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], packet[12:16]) // Source IP
	copy(pseudo[4:8], packet[16:20]) // Dest IP
	pseudo[8] = 0                    // Zero
	pseudo[9] = packet[9]            // Protocol (6 for TCP)
	pseudo[10] = byte(tcpLen >> 8)   // TCP length high
	pseudo[11] = byte(tcpLen & 0xFF) // TCP length low

	// Суммируем псевдозаголовок + TCP сегмент
	tcpData := packet[ipHeaderLen:]

	var sum uint32
	// Псевдозаголовок
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
	}
	// TCP заголовок + данные
	for i := 0; i < len(tcpData); i += 2 {
		if i+1 < len(tcpData) {
			sum += uint32(binary.BigEndian.Uint16(tcpData[i:]))
		} else {
			sum += uint32(tcpData[i]) << 8
		}
	}

	// Дополнение до 16 бит
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// FixTCPChecksum пересчитывает и устанавливает корректную TCP контрольную сумму
func FixTCPChecksum(packet []byte) {
	if len(packet) < 40 {
		return
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpOffset := ipHeaderLen + 16 // позиция checksum в TCP заголовке

	// Обнуляем текущую checksum
	packet[tcpOffset] = 0
	packet[tcpOffset+1] = 0

	// Вычисляем новую
	checksum := CalculateTCPChecksum(packet)
	packet[tcpOffset] = byte(checksum >> 8)
	packet[tcpOffset+1] = byte(checksum & 0xFF)
}
