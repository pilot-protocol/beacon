// SPDX-License-Identifier: AGPL-3.0-or-later

package wss_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	cw "github.com/coder/websocket"

	"github.com/pilot-protocol/beacon/wss"
	"github.com/pilot-protocol/common/crypto"
)

// startServer starts a real wss.Server on an ephemeral loopback port
// with caller-chosen timeouts and returns its ws:// URL.
func startServer(t *testing.T, pubKeys map[uint32]ed25519.PublicKey, idle, write time.Duration) (*wss.Server, string) {
	t.Helper()
	s, err := wss.New(wss.Config{
		BindAddr:     "127.0.0.1:0",
		AuthTimeout:  2 * time.Second,
		IdleTimeout:  idle,
		WriteTimeout: write,
		PubKeyLookup: func(id uint32) (ed25519.PublicKey, bool) {
			k, ok := pubKeys[id]
			return k, ok
		},
		OnFrame: func(uint32, []byte) {},
	})
	if err != nil {
		t.Fatalf("wss.New: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Server.Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, waitForServer(t, s)
}

// rawPeer dials the compat endpoint and completes the Ed25519 auth
// handshake by hand, returning the live connection.
//
// It deliberately does not use the daemon transport: that transport
// reconnects on its own, which makes "this connection was replaced"
// scenarios impossible to observe — the replaced side immediately dials
// back in and replaces its replacement, forever. A raw connection stays
// down once the server closes it.
func rawPeer(t *testing.T, wsURL string, id *crypto.Identity, nodeID uint32) *cw.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := cw.Dial(ctx, wsURL, &cw.DialOptions{Subprotocols: []string{"pilot.v1"}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetReadLimit(wss.MaxFrameSize)
	t.Cleanup(func() { _ = conn.CloseNow() })

	_, chBytes, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var challenge struct {
		Type      string `json:"type"`
		Nonce     string `json:"nonce"`
		Timestamp int64  `json:"ts"`
	}
	if err := json.Unmarshal(chBytes, &challenge); err != nil {
		t.Fatalf("parse challenge: %v", err)
	}

	signed := fmt.Sprintf("compat_auth:%d:%d:%s", nodeID, challenge.Timestamp, challenge.Nonce)
	sig := ed25519.Sign(ed25519.PrivateKey(id.PrivateKey), []byte(signed))
	reply, _ := json.Marshal(map[string]any{
		"type":       "auth_reply",
		"node_id":    nodeID,
		"public_key": base64.StdEncoding.EncodeToString(id.PublicKey),
		"sig":        base64.StdEncoding.EncodeToString(sig),
	})
	if err := conn.Write(ctx, cw.MessageText, reply); err != nil {
		t.Fatalf("write auth reply: %v", err)
	}
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read auth_ok: %v", err)
	}
	return conn
}

// TestServer_ReplacedPeerDoesNotEvictItsReplacement pins the peer-map
// ownership rule: when a node reconnects, the previous connection's read
// loop unwinds and runs its cleanup, and that cleanup must not remove
// the connection that replaced it. Otherwise the node is registered as
// connected for a moment and then silently deregistered, and every relay
// for a peer that only has a WSS path is dropped as unroutable.
func TestServer_ReplacedPeerDoesNotEvictItsReplacement(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	nodeID := uint32(31337)

	s, wsURL := startServer(t, map[uint32]ed25519.PublicKey{
		nodeID: ed25519.PublicKey(id.PublicKey),
	}, 30*time.Second, 2*time.Second)

	rawPeer(t, wsURL, id, nodeID)
	if !waitForCondition(2*time.Second, func() bool { return s.IsConnected(nodeID) }) {
		t.Fatal("first connection never registered")
	}

	// Same node reconnects. handleUpgrade installs the new connection
	// and closes the old one, which unblocks the old read loop.
	second := rawPeer(t, wsURL, id, nodeID)

	// The replacement must stay registered while the old read loop
	// finishes unwinding.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !s.IsConnected(nodeID) {
			t.Fatal("node deregistered after reconnect: the replaced connection's cleanup removed its replacement")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// And it must actually be usable.
	payload := []byte("to-the-live-connection")
	if !s.WriteFrame(nodeID, payload) {
		t.Fatal("WriteFrame to the reconnected node returned false")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	typ, frame, err := second.Read(ctx)
	if err != nil {
		t.Fatalf("Read on the live connection: %v", err)
	}
	if typ != cw.MessageBinary || string(frame) != string(payload) {
		t.Errorf("read frame = %q (type %v); want %q binary", frame, typ, payload)
	}
}

// TestServer_WriteFrameIsBoundedByWriteTimeout pins that one outbound
// frame cannot pin the calling goroutine for the idle window. The
// beacon's relay workers call WriteFrame, so the write deadline is the
// longest a worker can be held by a peer that stopped draining its
// socket; the idle window is orders of magnitude longer.
func TestServer_WriteFrameIsBoundedByWriteTimeout(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	nodeID := uint32(24680)

	const (
		idleTimeout  = 60 * time.Second
		writeTimeout = 300 * time.Millisecond
		// Generous headroom over writeTimeout, but far below
		// idleTimeout, so the assertion distinguishes the two.
		bound = 15 * time.Second
	)

	s, wsURL := startServer(t, map[uint32]ed25519.PublicKey{
		nodeID: ed25519.PublicKey(id.PublicKey),
	}, idleTimeout, writeTimeout)

	// Authenticate, then never read again, so the server's writes back
	// up in the kernel buffers.
	rawPeer(t, wsURL, id, nodeID)
	if !waitForCondition(2*time.Second, func() bool { return s.IsConnected(nodeID) }) {
		t.Fatal("stalled peer never registered")
	}

	frame := make([]byte, 256*1024)
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		for i := 0; i < 2000; i++ {
			if !s.WriteFrame(nodeID, frame) {
				done <- time.Since(start)
				return
			}
		}
		done <- -1
	}()

	select {
	case elapsed := <-done:
		if elapsed < 0 {
			t.Fatal("2000 writes to a peer that never reads all reported success")
		}
		if elapsed > bound {
			t.Fatalf("WriteFrame blocked for %s on a stalled peer; the write deadline should bound it near %s, not the %s idle window",
				elapsed, writeTimeout, idleTimeout)
		}
	case <-time.After(bound):
		t.Fatalf("WriteFrame still blocked after %s on a stalled peer; the write deadline should bound it near %s, not the %s idle window",
			bound, writeTimeout, idleTimeout)
	}

	// A peer whose write timed out is dropped, so the relay router stops
	// selecting it instead of retrying into the same stall.
	if !waitForCondition(2*time.Second, func() bool { return !s.IsConnected(nodeID) }) {
		t.Error("peer still registered after its write deadline expired; it should have been dropped")
	}
}

// TestServer_WriteTimeoutDefaults pins the default so a caller that does
// not set WriteTimeout still gets a bounded write rather than the idle
// window.
func TestServer_WriteTimeoutDefaults(t *testing.T) {
	t.Parallel()
	if wss.DefaultWriteTimeout >= wss.DefaultIdleTimeout {
		t.Fatalf("DefaultWriteTimeout (%s) must be well below DefaultIdleTimeout (%s)",
			wss.DefaultWriteTimeout, wss.DefaultIdleTimeout)
	}
}
