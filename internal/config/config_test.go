package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	t.Setenv("DGP_STATIC_KEY", strings.Repeat("01", 32))
	t.Setenv("DGP_ADDRESS", "127.0.0.1:9000")
	t.Setenv("DGP_IDLE_TIMEOUT", "45s")
	t.Setenv("DGP_KEEPALIVE_INTERVAL", "15s")
	t.Setenv("DGP_OUTBOUND_QUEUE", "8")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "127.0.0.1:9000" || cfg.IdleTimeout != 45*time.Second || cfg.KeepaliveInterval != 15*time.Second || cfg.OutboundQueue != 8 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadRequiresStaticKey(t *testing.T) {
	t.Setenv("DGP_STATIC_KEY", "")
	_, err := Load()
	if !errors.Is(err, ErrStaticKeyRequired) {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	t.Setenv("DGP_STATIC_KEY", strings.Repeat("01", 32))
	t.Setenv("DGP_READ_TIMEOUT", "never")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid duration error")
	}
}
