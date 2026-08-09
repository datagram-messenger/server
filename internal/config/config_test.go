package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testStatic = "0101010101010101010101010101010101010101010101010101010101010101"
	testPeer   = "0202020202020202020202020202020202020202020202020202020202020202"
)

func TestLoadDefaults(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("DGP_STATIC_KEY", testStatic)
	t.Setenv("DGP_PEER_IDENTITIES", testPeer+"=alice")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8090" || cfg.HandshakeTimeout != 10*time.Second || cfg.ReadTimeout != 0 || cfg.IdleTimeout != 2*time.Minute || cfg.OutboundQueue != 64 || cfg.MaxActiveConnections != 1024 {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestLoadYAMLAndEnvironmentPrecedence(t *testing.T) {
	clearConfigEnv(t)
	path := writeConfig(t, `
address: 127.0.0.1:9000
static_key: '`+testStatic+`'
peer_identities:
  '`+testPeer+`': alice
idle_timeout: 2m
keepalive_interval: 20s
keepalive_timeout: 40s
outbound_queue: 8
`)
	t.Setenv("DGP_ADDRESS", "127.0.0.1:9100")
	t.Setenv("DGP_OUTBOUND_QUEUE", "9")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "127.0.0.1:9100" || cfg.OutboundQueue != 9 || cfg.KeepaliveInterval != 20*time.Second {
		t.Fatalf("unexpected precedence result: %#v", cfg)
	}
}

func TestLoadFileFailures(t *testing.T) {
	clearConfigEnv(t)
	t.Run("explicit missing", func(t *testing.T) {
		if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.Contains(err.Error(), "read file") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		if _, err := Load(writeConfig(t, "address: [\n")); err == nil {
			t.Fatal("expected malformed YAML error")
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		path := writeConfig(t, "static_key: '"+testStatic+"'\npeer_identities:\n  '"+testPeer+"': alice\nunknown_option: true\n")
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown_option") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestLoadValidation(t *testing.T) {
	clearConfigEnv(t)
	tests := []struct{ name, extra, field string }{
		{"address", "address: localhost\n", "address"},
		{"duration", "handshake_timeout: 0s\n", "handshake_timeout"},
		{"timeout relationship", "idle_timeout: 30s\nkeepalive_interval: 20s\nkeepalive_timeout: 20s\n", "idle_timeout"},
		{"queue", "handler_queue: 0\n", "handler_queue"},
		{"limits", "max_concurrent_handshakes: 20\nmax_active_connections: 10\n", "max_concurrent_handshakes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, "static_key: '"+testStatic+"'\npeer_identities:\n  '"+testPeer+"': alice\n"+tt.extra)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPeerIdentitiesAndLegacyEnvironment(t *testing.T) {
	clearConfigEnv(t)
	path := writeConfig(t, "static_key: '"+testStatic+"'\npeer_identities:\n  '"+testPeer+"': alice\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	for i := range key {
		key[i] = 2
	}
	if cfg.PeerIdentities[key] != "alice" {
		t.Fatalf("identity = %q", cfg.PeerIdentities[key])
	}

	t.Setenv("DGP_PEER_IDENTITIES", strings.Repeat("03", 32)+"=bob")
	cfg, err = Load(path)
	if err != nil || len(cfg.PeerIdentities) != 1 {
		t.Fatalf("legacy override: cfg=%#v err=%v", cfg, err)
	}
}

func TestSecretsAreNotLeaked(t *testing.T) {
	clearConfigEnv(t)
	secret := strings.Repeat("super-secret", 8)
	path := writeConfig(t, "static_key: "+secret+"\npeer_identities:\n  "+testPeer+": alice\n")
	_, err := Load(path)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestRequiresProductionIdentityAndKey(t *testing.T) {
	clearConfigEnv(t)
	_, err := Load("")
	if !errors.Is(err, ErrStaticKeyRequired) {
		t.Fatalf("error = %v", err)
	}
	t.Setenv("DGP_STATIC_KEY", testStatic)
	_, err = Load("")
	if !errors.Is(err, ErrPeerIdentitiesRequired) {
		t.Fatalf("error = %v", err)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range knownKeys {
		t.Setenv("DGP_"+strings.ToUpper(key), "")
	}
	if err := os.Unsetenv("DGP_PEER_IDENTITIES"); err != nil {
		t.Fatal(err)
	}
}
