package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const staticKeySize = 32

var (
	// ErrPeerIdentitiesRequired reports a fail-closed identity policy with no allowlist.
	ErrPeerIdentitiesRequired = errors.New("config: peer_identities is required")
	// ErrStaticKeyRequired reports that no server static key source was configured.
	ErrStaticKeyRequired = errors.New("config: static_key or static_key_file is required")
)

// Config contains validated runtime settings for the DGPv1 TCP server.
type Config struct {
	Address                 string
	StaticKey               [staticKeySize]byte
	PeerIdentities          map[[staticKeySize]byte]string
	HandshakeTimeout        time.Duration
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
	IdleTimeout             time.Duration
	KeepaliveInterval       time.Duration
	KeepaliveTimeout        time.Duration
	OutboundQueue           int
	HandlerQueue            int
	MaxConcurrentHandshakes int
	MaxActiveConnections    int
}

type fileConfig struct {
	Address                 string            `mapstructure:"address"`
	StaticKey               string            `mapstructure:"static_key"`
	StaticKeyFile           string            `mapstructure:"static_key_file"`
	PeerIdentities          map[string]string `mapstructure:"peer_identities"`
	HandshakeTimeout        time.Duration     `mapstructure:"handshake_timeout"`
	ReadTimeout             time.Duration     `mapstructure:"read_timeout"`
	WriteTimeout            time.Duration     `mapstructure:"write_timeout"`
	IdleTimeout             time.Duration     `mapstructure:"idle_timeout"`
	KeepaliveInterval       time.Duration     `mapstructure:"keepalive_interval"`
	KeepaliveTimeout        time.Duration     `mapstructure:"keepalive_timeout"`
	OutboundQueue           int               `mapstructure:"outbound_queue"`
	HandlerQueue            int               `mapstructure:"handler_queue"`
	MaxConcurrentHandshakes int               `mapstructure:"max_concurrent_handshakes"`
	MaxActiveConnections    int               `mapstructure:"max_active_connections"`
}

var knownKeys = []string{
	"address", "static_key", "static_key_file", "peer_identities",
	"handshake_timeout", "read_timeout", "write_timeout", "idle_timeout",
	"keepalive_interval", "keepalive_timeout", "outbound_queue", "handler_queue",
	"max_concurrent_handshakes", "max_active_connections",
}

// Load loads defaults, an optional YAML file, environment overrides, and then
// validates and converts secrets. An explicit path must exist; an empty path
// searches ./config.yaml and ./config/config.yaml without consulting user home.
func Load(explicitPath string) (Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("DGP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	setDefaults(v)
	for _, key := range knownKeys {
		// DGP_PEER_IDENTITIES keeps its legacy comma-separated representation and
		// is parsed separately instead of being unmarshaled into the YAML map.
		if key == "peer_identities" {
			continue
		}
		if err := v.BindEnv(key); err != nil {
			return Config{}, fmt.Errorf("config: bind %s: %w", key, err)
		}
	}

	if explicitPath != "" {
		v.SetConfigFile(explicitPath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
	}
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if explicitPath != "" || !errors.As(err, &notFound) {
			return Config{}, fmt.Errorf("config: read file: %w", err)
		}
	}

	var raw fileConfig
	if err := v.UnmarshalExact(&raw, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}
	if legacy, ok := os.LookupEnv("DGP_PEER_IDENTITIES"); ok {
		identities, err := parseLegacyPeerIdentities(legacy)
		if err != nil {
			return Config{}, err
		}
		raw.PeerIdentities = identities
	}
	return validate(raw)
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("address", ":8090")
	v.SetDefault("handshake_timeout", 10*time.Second)
	v.SetDefault("read_timeout", time.Duration(0))
	v.SetDefault("write_timeout", 10*time.Second)
	v.SetDefault("idle_timeout", 2*time.Minute)
	v.SetDefault("keepalive_interval", 30*time.Second)
	v.SetDefault("keepalive_timeout", 60*time.Second)
	v.SetDefault("outbound_queue", 64)
	v.SetDefault("handler_queue", 64)
	v.SetDefault("max_concurrent_handshakes", 64)
	v.SetDefault("max_active_connections", 1024)
}

func validate(raw fileConfig) (Config, error) {
	cfg := Config{
		Address: raw.Address, HandshakeTimeout: raw.HandshakeTimeout, ReadTimeout: raw.ReadTimeout,
		WriteTimeout: raw.WriteTimeout, IdleTimeout: raw.IdleTimeout,
		KeepaliveInterval: raw.KeepaliveInterval, KeepaliveTimeout: raw.KeepaliveTimeout,
		OutboundQueue: raw.OutboundQueue, HandlerQueue: raw.HandlerQueue,
		MaxConcurrentHandshakes: raw.MaxConcurrentHandshakes, MaxActiveConnections: raw.MaxActiveConnections,
	}
	if err := validateAddress(raw.Address); err != nil {
		return Config{}, err
	}
	if raw.StaticKey != "" && raw.StaticKeyFile != "" {
		return Config{}, errors.New("config: static_key and static_key_file are mutually exclusive")
	}
	keyText := raw.StaticKey
	if raw.StaticKeyFile != "" {
		value, err := os.ReadFile(raw.StaticKeyFile)
		if err != nil {
			return Config{}, fmt.Errorf("config: static_key_file: cannot read key: %w", err)
		}
		keyText = strings.TrimSpace(string(value))
	}
	if keyText == "" {
		return Config{}, ErrStaticKeyRequired
	}
	decoded, err := hex.DecodeString(keyText)
	if err != nil || len(decoded) != staticKeySize {
		return Config{}, fmt.Errorf("config: static_key must be %d hex-encoded bytes", staticKeySize)
	}
	copy(cfg.StaticKey[:], decoded)

	cfg.PeerIdentities, err = decodePeerIdentities(raw.PeerIdentities)
	if err != nil {
		return Config{}, err
	}
	for field, value := range map[string]time.Duration{
		"handshake_timeout": raw.HandshakeTimeout, "write_timeout": raw.WriteTimeout,
		"idle_timeout": raw.IdleTimeout, "keepalive_interval": raw.KeepaliveInterval,
		"keepalive_timeout": raw.KeepaliveTimeout,
	} {
		if value <= 0 {
			return Config{}, fmt.Errorf("config: %s must be a positive duration", field)
		}
	}
	if raw.ReadTimeout < 0 {
		return Config{}, errors.New("config: read_timeout must be a non-negative duration")
	}
	livenessWindow := max(raw.IdleTimeout, raw.KeepaliveInterval+raw.KeepaliveTimeout)
	if raw.ReadTimeout > 0 && raw.ReadTimeout < livenessWindow {
		return Config{}, errors.New("config: read_timeout must be zero or at least the idle/keepalive liveness window")
	}
	if raw.IdleTimeout < raw.KeepaliveInterval+raw.KeepaliveTimeout {
		return Config{}, errors.New("config: idle_timeout must be at least keepalive_interval + keepalive_timeout")
	}
	for field, value := range map[string]int{
		"outbound_queue": raw.OutboundQueue, "handler_queue": raw.HandlerQueue,
		"max_concurrent_handshakes": raw.MaxConcurrentHandshakes,
		"max_active_connections":    raw.MaxActiveConnections,
	} {
		if value <= 0 {
			return Config{}, fmt.Errorf("config: %s must be a positive integer", field)
		}
	}
	if raw.MaxConcurrentHandshakes > raw.MaxActiveConnections {
		return Config{}, errors.New("config: max_concurrent_handshakes must not exceed max_active_connections")
	}
	return cfg, nil
}

func validateAddress(address string) error {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("config: address must be a valid host:port listen address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("config: address port must be between 1 and 65535")
	}
	return nil
}

func decodePeerIdentities(values map[string]string) (map[[staticKeySize]byte]string, error) {
	if len(values) == 0 {
		return nil, ErrPeerIdentitiesRequired
	}
	entries := make(map[[staticKeySize]byte]string, len(values))
	principals := make(map[string]struct{}, len(values))
	for encoded, principal := range values {
		decoded, err := hex.DecodeString(encoded)
		if err != nil || len(decoded) != staticKeySize {
			return nil, errors.New("config: peer_identities contains an invalid Noise public key")
		}
		if principal == "" || strings.TrimSpace(principal) != principal {
			return nil, errors.New("config: peer_identities contains an empty or whitespace-padded principal")
		}
		if _, exists := principals[principal]; exists {
			return nil, errors.New("config: peer_identities contains a duplicate principal")
		}
		var key [staticKeySize]byte
		copy(key[:], decoded)
		entries[key] = principal
		principals[principal] = struct{}{}
	}
	return entries, nil
}

func parseLegacyPeerIdentities(value string) (map[string]string, error) {
	if value == "" {
		return nil, ErrPeerIdentitiesRequired
	}
	entries := make(map[string]string)
	for _, entry := range strings.Split(value, ",") {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.TrimSpace(entry) != entry {
			return nil, errors.New("config: peer_identities contains a malformed identity entry")
		}
		if _, exists := entries[parts[0]]; exists {
			return nil, errors.New("config: peer_identities contains a duplicate Noise public key")
		}
		entries[parts[0]] = parts[1]
	}
	return entries, nil
}
