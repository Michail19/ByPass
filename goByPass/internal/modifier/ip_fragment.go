package modifier

import (
	"encoding/binary"
	"fmt"
	"log"
)

// IPFragment представляет фрагментированный IP-пакет
type IPFragment struct {
	Data          []byte
	Offset        int
	MoreFragments bool
}

// FragmentIPPacket разбивает IP-пакет на фрагменты (RFC 791)
func FragmentIPPacket(packet []byte, mtu int) ([]*IPFragment, error) {
	// Add DF check
	df := (packet[6] & 0x40) != 0
	if df {
		log.Printf("DF bit set, skipping fragmentation")
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	if len(packet) < 20 {
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	// Проверяем IPv4
	if packet[0]>>4 != 4 {
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	// Парсим оригинальный IP-заголовок
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 {
		log.Printf("WARNING: Invalid IP header length: %d", ihl)
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) {
		log.Printf("WARNING: Packet length mismatch: header=%d, actual=%d", totalLen, len(packet))
		// Исправляем длину в заголовке
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		totalLen = len(packet)
	}

	id := binary.BigEndian.Uint16(packet[4:6])

	// Данные начинаются после заголовка
	//flags := packet[6] >> 5

	// Данные после заголовка
	if totalLen <= ihl {
		log.Printf("WARNING: No data in packet, totalLen=%d, ihl=%d", totalLen, ihl)
		return []*IPFragment{{Data: packet, Offset: 0, MoreFragments: false}}, nil
	}

	data := packet[ihl:totalLen]
	dataLen := len(data)

	// Максимальный размер данных во фрагменте (должен быть кратен 8)
	maxDataSize := (mtu - ihl) & ^7
	if maxDataSize <= 0 {
		maxDataSize = 1400
	}

	log.Printf("DEBUG: Fragmenting packet ID=%d, totalLen=%d, ihl=%d, dataLen=%d, maxDataSize=%d",
		id, totalLen, ihl, dataLen, maxDataSize)

	var fragments []*IPFragment
	offset := 0

	// Проверка на TLS перед фрагментацией
	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeaderOffset := ipHeaderLen
	tcpHeaderLen := int(packet[tcpHeaderOffset+12]>>4) * 4
	payloadOffset := ipHeaderLen + tcpHeaderLen
	isTLS := len(packet) > payloadOffset+5 && packet[payloadOffset] == 0x16 && packet[payloadOffset+1] == 0x03 && packet[payloadOffset+2] <= 0x03

	for offset < dataLen {
		// Размер данных для этого фрагмента
		thisDataSize := maxDataSize
		if offset+thisDataSize > dataLen {
			thisDataSize = dataLen - offset
		}

		// Для TLS пакетов проверяем, не разбили ли мы запись
		if isTLS && offset > 0 {
			// Проверяем, что не разбили TLS record посередине
			// Это сложно, лучше использовать TLS record splitting вместо IP фрагментации
			log.Printf("WARNING: IP fragmentation may break TLS records")
		}

		// Создаем заголовок фрагмента
		fragHeader := make([]byte, ihl)
		copy(fragHeader, packet[:ihl])

		// Устанавливаем длину
		fragTotalLen := ihl + thisDataSize
		binary.BigEndian.PutUint16(fragHeader[2:4], uint16(fragTotalLen))

		// Устанавливаем флаги и смещение
		moreFragsBit := uint16(0)
		if offset+thisDataSize < dataLen {
			moreFragsBit = 1 << 13 // MF bit
		}
		fragOffset := uint16(offset/8) & 0x1FFF     // 13 бит offset
		flagsAndOffset := moreFragsBit | fragOffset // DF bit игнорируем
		binary.BigEndian.PutUint16(fragHeader[6:8], flagsAndOffset)

		// Смещение в 8-байтовых блоках
		//fragHeader[6] = (flags & 0xE0) | byte(moreFragsBit<<5) | byte(fragOffset>>8&0x1F)
		//fragHeader[7] = byte(fragOffset & 0xFF)

		// Пересчитываем IP checksum
		binary.BigEndian.PutUint16(fragHeader[10:12], 0)
		checksum := calculateIPChecksum(fragHeader)
		binary.BigEndian.PutUint16(fragHeader[10:12], checksum)

		// Проверяем, что версия IP сохранилась
		if fragHeader[0]>>4 != 4 {
			log.Printf("CRITICAL: Fragment header lost IPv4 version! Got %d", fragHeader[0]>>4)
			// Принудительно устанавливаем версию
			fragHeader[0] = (fragHeader[0] & 0x0F) | 0x40
		}

		// Собираем фрагмент
		fragPacket := make([]byte, fragTotalLen)
		copy(fragPacket[:ihl], fragHeader)
		copy(fragPacket[ihl:], data[offset:offset+thisDataSize])

		fragments = append(fragments, &IPFragment{
			Data:          fragPacket,
			Offset:        offset,
			MoreFragments: moreFragsBit == 1,
		})

		offset += thisDataSize
	}

	return fragments, nil
}

// calculateIPChecksum вычисляет контрольную сумму IP-заголовка
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i+1 >= len(header) {
			sum += uint32(header[i]) << 8
		} else {
			sum += uint32(binary.BigEndian.Uint16(header[i:]))
		}
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
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

// FixTCPChecksum с проверками
func FixTCPChecksum(packet []byte) error {
	if len(packet) < 40 {
		return fmt.Errorf("packet too short")
	}

	ipHeaderLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHeaderLen+20 {
		return fmt.Errorf("packet too short for TCP header")
	}

	// Проверяем, что это TCP
	if packet[9] != 6 {
		return nil // Не TCP, не трогаем
	}

	// Проверяем длину TCP заголовка
	tcpHeaderLen := int(packet[ipHeaderLen+12]>>4) * 4
	if tcpHeaderLen < 20 || tcpHeaderLen > 60 {
		return fmt.Errorf("invalid TCP header length: %d", tcpHeaderLen)
	}

	tcpOffset := ipHeaderLen + 16
	packet[tcpOffset] = 0
	packet[tcpOffset+1] = 0

	checksum := CalculateTCPChecksum(packet)
	packet[tcpOffset] = byte(checksum >> 8)
	packet[tcpOffset+1] = byte(checksum & 0xFF)

	return nil
}
