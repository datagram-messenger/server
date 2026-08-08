package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

const staticKeySize = 32

// ErrStaticKeyRequired reports that DGP_STATIC_KEY was not set.
var ErrStaticKeyRequired = errors.New("config: DGP_STATIC_KEY is required")

// Config contains the runtime settings for the DGPv1 TCP server.
type Config struct {
	// Address is the TCP listen address from DGP_ADDRESS.
	Address string
	// StaticKey is the 32-byte server static key decoded from DGP_STATIC_KEY.
	StaticKey [staticKeySize]byte
	// HandshakeTimeout limits completion of the initial protocol handshake.
	HandshakeTimeout time.Duration
	// ReadTimeout limits each transport read operation.
	ReadTimeout time.Duration
	// WriteTimeout limits each transport write operation.
	WriteTimeout time.Duration
	// IdleTimeout limits elapsed time without inbound activity.
	IdleTimeout time.Duration
	// KeepaliveInterval controls how often the connection runtime sends keepalive messages.
	KeepaliveInterval time.Duration
	// KeepaliveTimeout limits how long an outstanding keepalive may remain unacknowledged.
	KeepaliveTimeout time.Duration
	// OutboundQueue is the capacity of the connection runtime's outbound queue.
	OutboundQueue int
	// HandlerQueue is the capacity of pending per-connection handler work.
	HandlerQueue int
	// MaxConcurrentHandshakes limits connections concurrently performing a handshake.
	MaxConcurrentHandshakes int
	// MaxActiveConnections limits authenticated connections retained by the server.
	MaxActiveConnections int
}

// Load reads configuration from environment variables. DGP_STATIC_KEY is
// required as exactly 32 hex-encoded bytes; invalid or non-positive timeout and
// queue values are rejected.
func Load() (Config, error) {
	cfg := Config{
		Address:                 envOr("DGP_ADDRESS", ":8090"),
		HandshakeTimeout:        10 * time.Second,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            10 * time.Second,
		IdleTimeout:             2 * time.Minute,
		KeepaliveInterval:       30 * time.Second,
		KeepaliveTimeout:        60 * time.Second,
		OutboundQueue:           64,
		HandlerQueue:            64,
		MaxConcurrentHandshakes: 64,
		MaxActiveConnections:    1024,
	}

	keyText := os.Getenv("DGP_STATIC_KEY")
	if keyText == "" {
		return Config{}, ErrStaticKeyRequired
	}
	key, err := hex.DecodeString(keyText)
	if err != nil || len(key) != staticKeySize {
		return Config{}, fmt.Errorf("config: DGP_STATIC_KEY must be %d hex-encoded bytes", staticKeySize)
	}
	copy(cfg.StaticKey[:], key)

	if cfg.HandshakeTimeout, err = durationEnv("DGP_HANDSHAKE_TIMEOUT", cfg.HandshakeTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ReadTimeout, err = durationEnv("DGP_READ_TIMEOUT", cfg.ReadTimeout); err != nil {
		return Config{}, err
	}
	if cfg.WriteTimeout, err = durationEnv("DGP_WRITE_TIMEOUT", cfg.WriteTimeout); err != nil {
		return Config{}, err
	}
	if cfg.IdleTimeout, err = durationEnv("DGP_IDLE_TIMEOUT", cfg.IdleTimeout); err != nil {
		return Config{}, err
	}
	if cfg.KeepaliveInterval, err = durationEnv("DGP_KEEPALIVE_INTERVAL", cfg.KeepaliveInterval); err != nil {
		return Config{}, err
	}
	if cfg.KeepaliveTimeout, err = durationEnv("DGP_KEEPALIVE_TIMEOUT", cfg.KeepaliveTimeout); err != nil {
		return Config{}, err
	}
	if cfg.OutboundQueue, err = positiveIntEnv("DGP_OUTBOUND_QUEUE", cfg.OutboundQueue); err != nil {
		return Config{}, err
	}
	if cfg.HandlerQueue, err = positiveIntEnv("DGP_HANDLER_QUEUE", cfg.HandlerQueue); err != nil {
		return Config{}, err
	}
	if cfg.MaxConcurrentHandshakes, err = positiveIntEnv("DGP_MAX_CONCURRENT_HANDSHAKES", cfg.MaxConcurrentHandshakes); err != nil {
		return Config{}, err
	}
	if cfg.MaxActiveConnections, err = positiveIntEnv("DGP_MAX_ACTIVE_CONNECTIONS", cfg.MaxActiveConnections); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func positiveIntEnv(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("config: %s must be a positive integer", key)
	}
	return parsed, nil
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("config: %s must be a positive duration", key)
	}
	return duration, nil
}
