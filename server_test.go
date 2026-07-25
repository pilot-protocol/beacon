// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// helper: send a discover message to register a node with a beacon
func registerNode(t *testing.T, beaconAddr *net.UDPAddr, nodeID uint32) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, beaconAddr)
	if err != nil {
		t.Fatalf("dial beacon: %v", err)
	}

	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], nodeID)
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("send discover: %v", err)
	}

	// Read discover reply
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read discover reply: %v", err)
	}
	if n < 1 || buf[0] != protocol.BeaconMsgDiscoverReply {
		t.Fatalf("unexpected reply type: 0x%02x", buf[0])
	}

	return conn
}

func beaconUDPAddr(t *testing.T, s *Server) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", s.Addr().String())
	if err != nil {
		t.Fatalf("resolve beacon addr: %v", err)
	}
	return addr
}

// waitUntil polls fn() every 10ms until it returns true or the timeout
// expires. Used in place of fixed sleeps so CI runners under `-race`
// aren't pinned to receive-goroutine-drain assumptions.
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

func TestGossip(t *testing.T) {
	t.Parallel()

	// Start two beacons — they'll be peers of each other
	b1 := NewWithPeers(1, nil) // peers set after both bind
	b2 := NewWithPeers(2, nil)

	go b1.ListenAndServe("127.0.0.1:0")
	go b2.ListenAndServe("127.0.0.1:0")
	<-b1.Ready()
	<-b2.Ready()
	defer b1.Close()
	defer b2.Close()

	b1Addr := beaconUDPAddr(t, b1)
	b2Addr := beaconUDPAddr(t, b2)

	// Set peers manually (after bind, so we know the ports)
	b1.peers = []*net.UDPAddr{b2Addr}
	b2.peers = []*net.UDPAddr{b1Addr}

	// Register node 100 on beacon 1
	conn1 := registerNode(t, b1Addr, 100)
	defer conn1.Close()

	// Register node 200 on beacon 2
	conn2 := registerNode(t, b2Addr, 200)
	defer conn2.Close()

	// Verify local counts
	if b1.LocalNodeCount() != 1 {
		t.Fatalf("b1 local nodes: got %d, want 1", b1.LocalNodeCount())
	}
	if b2.LocalNodeCount() != 1 {
		t.Fatalf("b2 local nodes: got %d, want 1", b2.LocalNodeCount())
	}

	// Trigger gossip manually
	b1.sendGossip()
	b2.sendGossip()

	// Each beacon should know about the other's node via gossip
	if !waitUntil(2*time.Second, func() bool { return b1.PeerNodeCount() == 1 && b2.PeerNodeCount() == 1 }) {
		t.Errorf("b1 peer nodes: got %d, want 1", b1.PeerNodeCount())
		t.Errorf("b2 peer nodes: got %d, want 1", b2.PeerNodeCount())
	}
}

func TestCrossBeaconRelay(t *testing.T) {
	t.Parallel()

	b1 := NewWithPeers(1, nil)
	b2 := NewWithPeers(2, nil)

	go b1.ListenAndServe("127.0.0.1:0")
	go b2.ListenAndServe("127.0.0.1:0")
	<-b1.Ready()
	<-b2.Ready()
	defer b1.Close()
	defer b2.Close()

	b1Addr := beaconUDPAddr(t, b1)
	b2Addr := beaconUDPAddr(t, b2)

	b1.peers = []*net.UDPAddr{b2Addr}
	b2.peers = []*net.UDPAddr{b1Addr}

	// Register node 10 on beacon 1
	conn1 := registerNode(t, b1Addr, 10)
	defer conn1.Close()

	// Register node 20 on beacon 2
	conn2 := registerNode(t, b2Addr, 20)
	defer conn2.Close()

	// Gossip so b1 knows node 20 is on b2 — poll instead of fixed
	// sleep so this isn't tight under CI load.
	b1.sendGossip()
	b2.sendGossip()
	if !waitUntil(5*time.Second, func() bool {
		return b1.PeerNodeCount() >= 1 && b2.PeerNodeCount() >= 1
	}) {
		t.Fatal("gossip did not propagate before relay send")
	}

	// Node 10 sends relay to node 20 via beacon 1
	// beacon 1 should forward to beacon 2, which delivers to node 20
	payload := []byte("hello from node 10")
	relayMsg := make([]byte, 1+4+4+len(payload))
	relayMsg[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(relayMsg[1:5], 10) // sender
	binary.BigEndian.PutUint32(relayMsg[5:9], 20) // dest
	copy(relayMsg[9:], payload)

	if _, err := conn1.Write(relayMsg); err != nil {
		t.Fatalf("send relay: %v", err)
	}

	// Node 20 should receive a RelayDeliver. 10s deadline gives CI
	// runners under -race comfortable margin; happy path still ~10ms.
	buf := make([]byte, 1500)
	conn2.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn2.Read(buf)
	if err != nil {
		t.Fatalf("read relay deliver: %v", err)
	}

	if buf[0] != protocol.BeaconMsgRelayDeliver {
		t.Fatalf("expected RelayDeliver (0x%02x), got 0x%02x", protocol.BeaconMsgRelayDeliver, buf[0])
	}

	senderID := binary.BigEndian.Uint32(buf[1:5])
	if senderID != 10 {
		t.Fatalf("sender ID: got %d, want 10", senderID)
	}

	received := string(buf[5:n])
	if received != "hello from node 10" {
		t.Fatalf("payload: got %q, want %q", received, "hello from node 10")
	}
}

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	// Find a free port for health
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	healthAddr := ln.Addr().String()
	ln.Close()

	go s.ServeHealth(healthAddr)
	time.Sleep(100 * time.Millisecond) // let HTTP server start

	url := fmt.Sprintf("http://%s/healthz", healthAddr)

	// Should be healthy by default
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// /healthz always returns 200 regardless of drain state
	// (operational fingerprint — drain state should not be broadcast)
	s.SetHealthy(false)
	resp, err = http.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz after unhealthy: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 (no drain fingerprint), got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Return to healthy — still 200
	s.SetHealthy(true)
	resp, err = http.Get(url)
	if err != nil {
		t.Fatalf("GET /healthz after re-healthy: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSyncMessageParsing(t *testing.T) {
	t.Parallel()

	s := NewWithPeers(1, nil)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	// Build a sync message with 3 nodes
	nodeIDs := []uint32{100, 200, 300}
	msg := make([]byte, 1+4+2+4*len(nodeIDs))
	msg[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(msg[1:5], 2) // peer beacon ID
	binary.BigEndian.PutUint16(msg[5:7], uint16(len(nodeIDs)))
	for i, id := range nodeIDs {
		binary.BigEndian.PutUint32(msg[7+4*i:7+4*i+4], id)
	}

	// Send the sync message to the beacon
	conn, err := net.DialUDP("udp", nil, beaconUDPAddr(t, s))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("send sync: %v", err)
	}

	if !waitUntil(2*time.Second, func() bool { return s.PeerNodeCount() == 3 }) {
		t.Fatalf("peer nodes: got %d, want 3", s.PeerNodeCount())
	}
}

// TestServer_CloseIsIdempotent regression-guards the fix that wraps
// Server.Close() in sync.Once. Prior to the fix the second Close()
// re-invoked Close() on every already-closed *net.UDPConn in s.conns,
// surfacing "use of closed network connection" as firstErr.
func TestServer_CloseIsIdempotent(t *testing.T) {
	t.Parallel()

	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()

	if err := s.Close(); err != nil {
		t.Fatalf("first Close: unexpected error: %v", err)
	}

	// The bug: pre-fix this second call walked s.conns and re-closed
	// each *net.UDPConn, returning "use of closed network connection".
	// With sync.Once + cached closeErr it must be a no-op.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: expected no-op, got: %v", err)
	}

	// A third call for good measure — sync.Once guarantees the
	// teardown body runs exactly once regardless of call count.
	if err := s.Close(); err != nil {
		t.Fatalf("third Close: expected no-op, got: %v", err)
	}
}
