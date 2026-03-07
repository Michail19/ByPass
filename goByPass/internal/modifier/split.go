package modifier

import (
	"encoding/binary"
	"log"
)

// ApplySplit применяет разбиение пакета
func (pm *PacketModifier) ApplySplit(packet []byte, splitPos []int, alignSNI bool) ([][]byte, error) {
	if len(splitPos) == 0 {
		return [][]byte{packet}, nil
	}

	// Проверяем, что пакет достаточно большой
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		log.Printf("DEBUG: Packet too small for split (%d bytes), returning original", len(packet))
		return [][]byte{packet}, nil
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4
	payloadOffset := tcpHeaderOffset + tcpHeaderLen
	payloadLen := len(packet) - payloadOffset
	if payloadLen <= 0 {
		return [][]byte{packet}, nil
	}

	// Split at positions (like zapret split-pos)
	var segments [][]byte
	prevPos := 0
	for _, pos := range splitPos {
		if pos < 5 || (pos > 5 && pos%5 != 0) { // safe alignments
			log.Printf("Invalid split pos %d for TLS, skipping", pos)
			continue
		}

		if pos > prevPos && pos < payloadLen {
			segments = append(segments, packet[payloadOffset+prevPos:payloadOffset+pos])
			prevPos = pos
		}
	}
	segments = append(segments, packet[payloadOffset+prevPos:])

	// Create TCP segments
	var results [][]byte
	seq := binary.BigEndian.Uint32(packet[tcpHeaderOffset+4:])
	for _, seg := range segments {
		segLen := len(seg)
		newPkt := make([]byte, ipHeaderLen+tcpHeaderLen+segLen)
		copy(newPkt, packet[:payloadOffset])
		binary.BigEndian.PutUint16(newPkt[2:4], uint16(len(newPkt)))
		binary.BigEndian.PutUint32(newPkt[tcpHeaderOffset+4:], seq)
		copy(newPkt[payloadOffset:], seg)
		// Clear DF if set
		newPkt[6] &= ^byte(0x40)
		recalculateIPChecksum(newPkt)
		FixTCPChecksum(newPkt)
		results = append(results, newPkt)
		seq += uint32(segLen)
	}

	return results, nil
}

// SplitAtPosition разбивает пакет в указанной позиции
func SplitAtPosition(packet []byte, pos int) [][]byte {
	if pos <= 0 || pos >= len(packet) {
		return [][]byte{packet}
	}

	return [][]byte{
		packet[:pos],
		packet[pos:],
	}
}

// SplitAfterBytes разбивает после первого вхождения байта
func SplitAfterBytes(packet []byte, b byte) [][]byte {
	for i, v := range packet {
		if v == b {
			return SplitAtPosition(packet, i+1)
		}
	}
	return [][]byte{packet}
}
