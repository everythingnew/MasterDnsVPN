// Package mobile provides a gomobile-compatible wrapper around the MasterDnsVPN client.
// It exposes a flat API (no channels, contexts, or function parameters) that
// gomobile can bind for Android.
package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

// Client wraps the MasterDnsVPN client with a simple Start/Stop lifecycle.
type Client struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	c       *client.Client
	port    int
	running atomic.Bool
	errCh   chan error
}

// jsonConfig is the minimal JSON shape we serialize to pass into
// LoadClientConfigFromJSONBase64WithOverrides. Field names match MasterDnsVPN's
// TOML tag names so that decodeConfigJSONInto maps them correctly.
type jsonConfig struct {
	Domains              []string `json:"DOMAINS"`
	EncryptionKey        string   `json:"ENCRYPTION_KEY"`
	DataEncryptionMethod int      `json:"DATA_ENCRYPTION_METHOD"`
	ProtocolType         string   `json:"PROTOCOL_TYPE"`
	ListenIP             string   `json:"LISTEN_IP"`
	ListenPort           int      `json:"LISTEN_PORT"`
}

// NewClient creates a Client from individual parameters.
//
// Parameters:
//   - domains: comma-separated list of MasterDns tunnel domains
//   - encryptionKey: shared secret (required)
//   - encryptionMethod: 0=None 1=XOR 2=ChaCha20 3=AES-128 4=AES-192 5=AES-256
//   - resolversText: newline-separated resolver IPs (e.g. "8.8.8.8\n1.1.1.1")
//   - listenPort: local SOCKS5 port
//   - listenHost: local SOCKS5 bind address (e.g. "127.0.0.1")
func NewClient(domains string, encryptionKey string, encryptionMethod int, resolversText string, listenPort int, listenHost string) (*Client, error) {
	domainList := splitTrimmed(domains, ",")
	if len(domainList) == 0 {
		return nil, fmt.Errorf("masterdns: at least one domain is required")
	}
	if strings.TrimSpace(encryptionKey) == "" {
		return nil, fmt.Errorf("masterdns: encryption key is required")
	}
	if strings.TrimSpace(listenHost) == "" {
		listenHost = "127.0.0.1"
	}

	cfg := jsonConfig{
		Domains:              domainList,
		EncryptionKey:        encryptionKey,
		DataEncryptionMethod: encryptionMethod,
		ProtocolType:         "SOCKS5",
		ListenIP:             listenHost,
		ListenPort:           listenPort,
	}
	return newClientFromStruct(cfg, resolversText)
}

// NewClientFromJSON creates a Client from a base64-encoded JSON config string plus
// a newline-separated resolvers blob. The JSON uses MasterDnsVPN TOML field names
// (e.g. "DOMAINS", "ENCRYPTION_KEY"). Extra fields beyond what clientConfig
// declares are ignored; MasterDnsVPN defaults fill the rest.
//
// resolversText is the full text content of a client_resolvers.txt file.
func NewClientFromJSON(jsonBase64Str string, resolversText string) (*Client, error) {
	resolversPath, cleanup, err := writeTempResolvers(resolversText)
	if err != nil {
		return nil, fmt.Errorf("masterdns: resolver write failed: %w", err)
	}
	defer cleanup()

	overrides := config.ClientConfigOverrides{
		ResolversFilePath: &resolversPath,
	}
	loaded, err := config.LoadClientConfigFromJSONBase64WithOverrides(jsonBase64Str, overrides)
	if err != nil {
		return nil, fmt.Errorf("masterdns: config load failed: %w", err)
	}

	return buildClient(loaded)
}

func newClientFromStruct(cfg jsonConfig, resolversText string) (*Client, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("masterdns: config marshal failed: %w", err)
	}

	resolversPath, cleanup, err := writeTempResolvers(resolversText)
	if err != nil {
		return nil, fmt.Errorf("masterdns: resolver write failed: %w", err)
	}
	defer cleanup()

	encoded := base64.StdEncoding.EncodeToString(raw)
	overrides := config.ClientConfigOverrides{
		ResolversFilePath: &resolversPath,
	}
	loaded, err := config.LoadClientConfigFromJSONBase64WithOverrides(encoded, overrides)
	if err != nil {
		return nil, fmt.Errorf("masterdns: config load failed: %w", err)
	}

	return buildClient(loaded)
}

func buildClient(cfg config.ClientConfig) (*Client, error) {
	log := logger.New("MasterDnsVPN", cfg.LogLevel)
	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("masterdns: codec setup failed: %w", err)
	}
	c := client.New(cfg, log, codec)
	if err := c.BuildConnectionMap(); err != nil {
		return nil, fmt.Errorf("masterdns: connection map failed: %w", err)
	}

	return &Client{
		c:     c,
		port:  cfg.ListenPort,
		errCh: make(chan error, 1),
	}, nil
}

// Start launches the MasterDns client in the background and returns immediately.
// The client begins MTU discovery and session setup asynchronously.
func (cl *Client) Start() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.running.Load() {
		return fmt.Errorf("masterdns: already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cl.cancel = cancel
	cl.running.Store(true)

	go func() {
		defer cl.running.Store(false)
		if err := cl.c.Run(ctx); err != nil {
			select {
			case cl.errCh <- err:
			default:
			}
		}
	}()

	return nil
}

// Stop shuts down the client cleanly.
func (cl *Client) Stop() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.cancel != nil {
		cl.cancel()
		cl.cancel = nil
	}
}

// IsRunning returns true if the client goroutine is active.
func (cl *Client) IsRunning() bool {
	return cl.running.Load()
}

// GetPort returns the local SOCKS5 listen port.
func (cl *Client) GetPort() int {
	return cl.port
}

// --- helpers ---

func splitTrimmed(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeTempResolvers(text string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp(os.TempDir(), "masterdns-resolvers-*.txt")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temp resolver file: %w", err)
	}
	name := f.Name()
	cleanup = func() { os.Remove(name) }

	if _, err := f.WriteString(text); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("write resolvers: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close resolver file: %w", err)
	}

	abs, err := filepath.Abs(name)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return abs, cleanup, nil
}
