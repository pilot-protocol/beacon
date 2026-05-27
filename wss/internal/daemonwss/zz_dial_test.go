// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonwss_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"testing"
	"time"

	"github.com/pilot-protocol/beacon/wss"
	dwss "github.com/pilot-protocol/beacon/wss/internal/daemonwss"
	"github.com/pilot-protocol/common/crypto"
)

// waitUntil polls fn() every 10ms until it returns true or the
// timeout expires.
func waitUntil(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

// startWSS spins up a wss.Server bound to 127.0.0.1:0 that
// authenticates one specific nodeID. Returns the ws:// URL plus a
// teardown func.
func startWSS(t *testing.T, nodeID uint32, pub ed25519.PublicKey) (*wss.Server, string, func()) {
	t.Helper()
	s, err := wss.New(wss.Config{
		BindAddr:    "127.0.0.1:0",
		AuthTimeout: 2 * time.Second,
		IdleTimeout: 5 * time.Second,
		PubKeyLookup: func(id uint32) (ed25519.PublicKey, bool) {
			if id == nodeID {
				return pub, true
			}
			return nil, false
		},
		OnFrame: func(_ uint32, _ []byte) {},
	})
	if err != nil {
		t.Fatalf("wss.New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := s.Addr()
	url := "ws://" + addr + "/v1/compat"
	return s, url, func() { _ = s.Close() }
}

// TestDial_AndAuth_HappyPath drives Dial → dialAndAuth → runAuth →
// supervise. Covers the success path of every function in
// daemonwss/wss.go that the beacon's test suite uses indirectly but
// never reports coverage on (because the existing wss tests live in
// the wss package, not daemonwss).
func TestDial_AndAuth_HappyPath(t *testing.T) {
	t.Parallel()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	nodeID := uint32(7700)

	_, url, teardown := startWSS(t, nodeID, ed25519.PublicKey(id.PublicKey))
	defer teardown()

	tr, err := dwss.Dial(context.Background(), dwss.Config{
		URL:         url,
		TLSConfig:   &tls.Config{},
		Identity:    id,
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	if tr.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}

	// Send → covers the live-conn Send branch.
	if n, err := tr.Send([]byte("hello"), nil); err != nil || n != 5 {
		t.Errorf("Send = (%d, %v), want (5, nil)", n, err)
	}
}

// TestDial_RejectsMissingURL covers the URL-required validation.
func TestDial_RejectsMissingURL(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	_, err := dwss.Dial(context.Background(), dwss.Config{
		TLSConfig: &tls.Config{},
		Identity:  id,
		NodeID:    1,
	})
	if err == nil {
		t.Fatal("Dial with empty URL: want error")
	}
}

// TestDial_RejectsMissingTLSConfig covers the TLSConfig-required check.
func TestDial_RejectsMissingTLSConfig(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	_, err := dwss.Dial(context.Background(), dwss.Config{
		URL:      "ws://127.0.0.1:1/",
		Identity: id,
		NodeID:   1,
	})
	if err == nil {
		t.Fatal("Dial with nil TLSConfig: want error")
	}
}

// TestDial_RejectsMissingIdentity covers the Identity-required check.
func TestDial_RejectsMissingIdentity(t *testing.T) {
	t.Parallel()
	_, err := dwss.Dial(context.Background(), dwss.Config{
		URL:       "ws://127.0.0.1:1/",
		TLSConfig: &tls.Config{},
		NodeID:    1,
	})
	if err == nil {
		t.Fatal("Dial with nil Identity: want error")
	}
}

// TestDial_ConnectionRefused covers the dial-error path inside
// dialAndAuth (websocket.Dial returns an error against an unbound
// port).
func TestDial_ConnectionRefused(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	_, err := dwss.Dial(context.Background(), dwss.Config{
		URL:         "ws://127.0.0.1:1/v1/compat",
		TLSConfig:   &tls.Config{},
		Identity:    id,
		NodeID:      1,
		DialTimeout: 500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Dial against closed port: want error")
	}
}

// TestSend_AfterClose returns ErrClosed for closed transports.
func TestSend_AfterClose(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	nodeID := uint32(7701)
	_, url, teardown := startWSS(t, nodeID, ed25519.PublicKey(id.PublicKey))
	defer teardown()

	tr, err := dwss.Dial(context.Background(), dwss.Config{
		URL: url, TLSConfig: &tls.Config{},
		Identity: id, NodeID: nodeID, DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = tr.Close()

	// Subsequent Send → ErrClosed (covers the closed-flag branch).
	if _, err := tr.Send([]byte("x"), nil); err == nil {
		t.Error("Send after Close: want error")
	}
	// Recv after Close → ErrClosed (covers the !ok branch).
	if _, _, err := tr.Recv(); err == nil {
		t.Error("Recv after Close: want error")
	}
}

// TestClose_Idempotent covers the closeOnce path.
func TestClose_Idempotent(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	nodeID := uint32(7702)
	_, url, teardown := startWSS(t, nodeID, ed25519.PublicKey(id.PublicKey))
	defer teardown()

	tr, err := dwss.Dial(context.Background(), dwss.Config{
		URL: url, TLSConfig: &tls.Config{},
		Identity: id, NodeID: nodeID, DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close: %v (closeOnce must swallow)", err)
	}
}

// TestRecv_DeliveredFrame covers the supervise/drainReads → recvCh
// path. The server writes a binary frame; the daemon's Recv returns it.
func TestRecv_DeliveredFrame(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	nodeID := uint32(7703)
	s, url, teardown := startWSS(t, nodeID, ed25519.PublicKey(id.PublicKey))
	defer teardown()

	tr, err := dwss.Dial(context.Background(), dwss.Config{
		URL: url, TLSConfig: &tls.Config{},
		Identity: id, NodeID: nodeID, DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	if !waitUntil(time.Second, func() bool { return s.IsConnected(nodeID) }) {
		t.Fatal("peer never connected")
	}

	payload := []byte("hello from server")
	if !s.WriteFrame(nodeID, payload) {
		t.Fatal("WriteFrame returned false")
	}

	frameCh := make(chan []byte, 1)
	go func() {
		frame, _, err := tr.Recv()
		if err != nil {
			t.Errorf("Recv: %v", err)
			return
		}
		frameCh <- frame
	}()
	select {
	case got := <-frameCh:
		if string(got) != string(payload) {
			t.Errorf("got %q want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv timeout")
	}
}
