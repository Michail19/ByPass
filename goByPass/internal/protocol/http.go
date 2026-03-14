package protocol

import (
	"bytes"
	"strings"
)

// parseHTTP разбирает HTTP пакет и заполняет ConnectionInfo
func (a *Analyzer) parseHTTP(data []byte, info *ConnectionInfo) error {
	info.IsHTTP = true

	// Определяем, запрос это или ответ
	if bytes.HasPrefix(data, []byte("HTTP/")) {
		// Это HTTP ответ
		return a.parseHTTPResponse(data, info)
	}

	// Это HTTP запрос
	return a.parseHTTPRequest(data, info)
}

// parseHTTPRequest разбирает HTTP запрос
func (a *Analyzer) parseHTTPRequest(data []byte, info *ConnectionInfo) error {
	lines := bytes.SplitN(data, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return nil
	}

	// Парсим первую строку: "GET /path HTTP/1.1"
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) >= 1 {
		info.Method = string(parts[0])
	}
	if len(parts) >= 2 {
		info.Path = string(parts[1])
	}

	// Парсим заголовки
	if len(lines) >= 2 {
		a.parseHTTPHeaders(lines[1], info)
	}

	return nil
}

// parseHTTPResponse разбирает HTTP ответ
func (a *Analyzer) parseHTTPResponse(data []byte, info *ConnectionInfo) error {
	lines := bytes.SplitN(data, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return nil
	}

	// Парсим заголовки ответа
	if len(lines) >= 2 {
		a.parseHTTPHeaders(lines[1], info)
	}

	return nil
}

// parseHTTPHeaders разбирает HTTP заголовки
func (a *Analyzer) parseHTTPHeaders(data []byte, info *ConnectionInfo) {
	headers := bytes.Split(data, []byte("\r\n"))

	for _, header := range headers {
		if len(header) == 0 {
			continue
		}

		colon := bytes.IndexByte(header, ':')
		if colon <= 0 {
			continue
		}

		key := strings.ToLower(string(header[:colon]))
		value := strings.TrimSpace(string(header[colon+1:]))

		switch key {
		case "host":
			info.Host = value
		case "user-agent":
			info.UserAgent = value
		case "content-type":
			info.ContentType = value
		}
	}
}

// ExtractHost извлекает Host из HTTP запроса
func ExtractHost(data []byte) string {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if strings.EqualFold(string(line[:colon]), "host") {
			return strings.TrimSpace(string(line[colon+1:]))
		}
	}
	return ""
}
