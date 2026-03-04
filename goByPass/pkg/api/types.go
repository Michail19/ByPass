package api

// MobileConfig конфигурация для мобильных устройств
type MobileConfig struct {
	ServerAddr    string   `json:"server_addr"`
	ServerPort    int      `json:"server_port"`
	Password      string   `json:"password"`
	Protocol      string   `json:"protocol"` // "trojan", "v2ray", "shadowsocks"
	EnableVPN     bool     `json:"enable_vpn"`
	BypassDomains []string `json:"bypass_domains"`
	ProxyPort     int      `json:"proxy_port"`
}

// MobileStats статистика для мобильных устройств
type MobileStats struct {
	BytesReceived   int64 `json:"bytes_received"`
	BytesSent       int64 `json:"bytes_sent"`
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent     int64 `json:"packets_sent"`
	ActiveFlows     int   `json:"active_flows"`
	UptimeSeconds   int64 `json:"uptime_seconds"`
}
