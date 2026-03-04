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

		parts := bytes.SplitN(header, []byte(": "), 2)
		if len(parts) != 2 {
			continue
		}

		key := string(parts[0])
		value := string(parts[1])

		switch strings.ToLower(key) {
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
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				return strings.TrimSpace(string(parts[1]))
			}
		}
	}
	return ""
}
