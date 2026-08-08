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

var ErrStaticKeyRequired = errors.New("config: DGP_STATIC_KEY is required")

// Config contains the runtime settings for the DGPv1 TCP server.
type Config struct {
	Address           string
	StaticKey         [staticKeySize]byte
	HandshakeTimeout  time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	KeepaliveInterval time.Duration
	OutboundQueue     int
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		Address:           envOr("DGP_ADDRESS", ":8090"),
		HandshakeTimeout:  10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		KeepaliveInterval: 30 * time.Second,
		OutboundQueue:     64,
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
	if value := os.Getenv("DGP_OUTBOUND_QUEUE"); value != "" {
		cfg.OutboundQueue, err = strconv.Atoi(value)
		if err != nil || cfg.OutboundQueue <= 0 {
			return Config{}, errors.New("config: DGP_OUTBOUND_QUEUE must be a positive integer")
		}
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
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
