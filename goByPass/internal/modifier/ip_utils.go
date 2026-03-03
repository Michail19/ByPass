package modifier

import (
	"encoding/binary"
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

// ExtractPorts извлекает source и destination порты
func ExtractPorts(packet []byte) (srcPort, dstPort uint16, err error) {
	if len(packet) < 20 {
		return 0, 0, nil
	}

	ipHeaderLen := (packet[0] & 0x0F) * 4
	if len(packet) < int(ipHeaderLen)+4 {
		return 0, 0, nil
	}

	tcpHeaderOffset := int(ipHeaderLen)
	srcPort = binary.BigEndian.Uint16(packet[tcpHeaderOffset:])
	dstPort = binary.BigEndian.Uint16(packet[tcpHeaderOffset+2:])

	return srcPort, dstPort, nil
}
