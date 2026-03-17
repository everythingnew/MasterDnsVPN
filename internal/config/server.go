// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

type ServerConfig struct {
	UDPHost               string `toml:"UDP_HOST"`
	UDPPort               int    `toml:"UDP_PORT"`
	SocketBufferSize      int    `toml:"SOCKET_BUFFER_SIZE"`
	MaxConcurrentRequests int    `toml:"MAX_CONCURRENT_REQUESTS"`
	DNSRequestWorkers     int    `toml:"DNS_REQUEST_WORKERS"`
	MaxPacketSize         int    `toml:"MAX_PACKET_SIZE"`
	LogLevel              string `toml:"LOG_LEVEL"`
}

func defaultServerConfig() ServerConfig {
	workers := runtime.NumCPU() * 2
	if workers < 2 {
		workers = 2
	}
	if workers > 32 {
		workers = 32
	}

	return ServerConfig{
		UDPHost:               "0.0.0.0",
		UDPPort:               53,
		SocketBufferSize:      8 * 1024 * 1024,
		MaxConcurrentRequests: 4096,
		DNSRequestWorkers:     workers,
		MaxPacketSize:         4096,
		LogLevel:              "INFO",
	}
}

func LoadServerConfig(filename string) (ServerConfig, error) {
	cfg := defaultServerConfig()
	path, err := filepath.Abs(filename)
	if err != nil {
		return cfg, err
	}

	if _, err := os.Stat(path); err != nil {
		return cfg, fmt.Errorf("config file not found: %s", path)
	}

	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parse TOML failed for %s: %w", path, err)
	}

	if cfg.UDPHost == "" {
		cfg.UDPHost = "0.0.0.0"
	}
	if cfg.UDPPort <= 0 || cfg.UDPPort > 65535 {
		return cfg, fmt.Errorf("invalid UDP_PORT: %d", cfg.UDPPort)
	}
	if cfg.SocketBufferSize <= 0 {
		cfg.SocketBufferSize = 8 * 1024 * 1024
	}
	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = 4096
	}
	if cfg.DNSRequestWorkers <= 0 {
		cfg.DNSRequestWorkers = defaultServerConfig().DNSRequestWorkers
	}
	if cfg.MaxPacketSize <= 0 {
		cfg.MaxPacketSize = 4096
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	return cfg, nil
}

func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.UDPHost, c.UDPPort)
}
