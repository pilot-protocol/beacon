// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"testing"
)

// TestNew_ReturnsUsableServer covers the New helper and the
// counter accessors (RelayForwarded / RelayDropped / RelayNotFound).
func TestNew_ReturnsUsableServer(t *testing.T) {
	t.Parallel()
	s := New()
	if s == nil {
		t.Fatal("New returned nil")
	}
	if got := s.RelayForwarded(); got != 0 {
		t.Errorf("RelayForwarded = %d, want 0", got)
	}
	if got := s.RelayDropped(); got != 0 {
		t.Errorf("RelayDropped = %d, want 0", got)
	}
	if got := s.RelayNotFound(); got != 0 {
		t.Errorf("RelayNotFound = %d, want 0", got)
	}
}

// TestNewWithPeers_BadPeerAddressIsSkipped covers the
// net.ResolveUDPAddr error branch.
func TestNewWithPeers_BadPeerAddressIsSkipped(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(42, []string{"not a host"})
	if s == nil {
		t.Fatal("NewWithPeers returned nil")
	}
	if got := len(s.peers); got != 0 {
		t.Errorf("len(peers) = %d, want 0 (bad peer was skipped)", got)
	}
}

// TestNewWithPeers_GoodPeerRegistered covers the happy parse branch.
func TestNewWithPeers_GoodPeerRegistered(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(7, []string{"127.0.0.1:9999"})
	if got := len(s.peers); got != 1 {
		t.Errorf("len(peers) = %d, want 1", got)
	}
}

// TestServer_SetRegistryAccessors exercises the registry/advert/admin setters.
func TestServer_SetRegistryAccessors(t *testing.T) {
	t.Parallel()
	s := New()
	s.SetRegistry("registry.example:9000")
	s.SetAdvertiseAddr("203.0.113.5:4000")
	s.SetRegistryAdminToken("ADMIN")
	// These are write-only setters; their effect is observed via the
	// register loop. We just verify they don't panic.
}

// TestServer_CompatWSSAccessorsOnEmptyServer cover the "wssServer nil"
// branches.
func TestServer_CompatWSSAccessorsOnEmptyServer(t *testing.T) {
	t.Parallel()
	s := New()
	// WSSMetrics on no-wss server: zero values.
	_ = s.WSSMetrics()
	// WSSAddr on no-wss server: empty.
	if got := s.WSSAddr(); got != "" {
		t.Errorf("WSSAddr no-wss: got %q, want empty", got)
	}
	// WSSIsConnected on no-wss server: false.
	if s.WSSIsConnected(123) {
		t.Error("WSSIsConnected no-wss: want false")
	}
	// CloseCompatWSS on no-wss server: nil error.
	if err := s.CloseCompatWSS(); err != nil {
		t.Errorf("CloseCompatWSS no-wss: %v", err)
	}
}
