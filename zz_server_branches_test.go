// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestClose_DoneChannelIdempotent pins the `select` fallthrough
// branch on the second Close: the s.done channel is already closed,
// so the second invocation hits the default-case no-op rather than
// double-closing the channel (which would panic).
//
// Note: Close also re-invokes net.UDPConn.Close on conns that were
// already closed on the first call — that returns "use of closed
// network connection", which the function bubbles up as firstErr.
// We only care that Close doesn't panic on the second call.
func TestClose_DoneChannelIdempotent(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	if err := s.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	// Second close: must not panic. Underlying conns will report
	// already-closed, which is fine.
	_ = s.Close()
}

// TestSendPunchCommand_MissingNode exercises the error branch when
// Snapshot returns ok=false. Wraps protocol.ErrNodeNotFound so the
// caller can errors.Is-check.
func TestSendPunchCommand_MissingNode(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	err := s.SendPunchCommand(99999, net.IPv4(10, 0, 0, 1), 4000)
	if err == nil {
		t.Fatal("expected error for missing node")
	}
	if !errors.Is(err, protocol.ErrNodeNotFound) {
		t.Errorf("err = %v, want wraps ErrNodeNotFound", err)
	}
}

// TestSendPunchCommand_IPv6 exercises the IPv6 encoding path.
func TestSendPunchCommand_IPv6(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	// Register a fake node so Snapshot returns ok.
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4444}
	s.nodes.Upsert(7, addr, time.Now(), maxBeaconNodes)

	// Encode an IPv6 target — the function picks the To4()==nil branch
	// and writes 16 bytes for the IP.
	v6 := net.ParseIP("2001:db8::1")
	if v6 == nil {
		t.Fatal("ParseIP")
	}
	// We can't actually deliver to 127.0.0.1:4444 since nothing's
	// listening — WriteToUDP just enqueues the packet on the local UDP
	// socket. The function returns nil even if the destination is dead.
	if err := s.SendPunchCommand(7, v6, 5555); err != nil {
		t.Errorf("SendPunchCommand: %v", err)
	}
}

// TestDispatchRelay_OversizePayloadDropped covers the maxRelayPayload
// guard. We can't actually deliver a >65k UDP datagram easily; we
// exercise the branch by calling dispatchRelay directly.
func TestDispatchRelay_OversizePayloadDropped(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	// Register the dest so the dispatch passes the pre-check, then we
	// hit the oversize-payload drop branch.
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	s.nodes.Upsert(11, addr, time.Now(), maxBeaconNodes)

	data := make([]byte, 8+maxRelayPayload+1)
	binary.BigEndian.PutUint32(data[0:4], 1)
	binary.BigEndian.PutUint32(data[4:8], 11)
	s.dispatchRelay(data)
	// No assertion — we just want the branch hit (and no panic).
}

// TestDispatchRelay_TooShortNoOp exercises the early-return when the
// caller passes fewer than 8 bytes.
func TestDispatchRelay_TooShortNoOp(t *testing.T) {
	t.Parallel()
	s := New()
	defer s.Close()
	s.dispatchRelay([]byte{0x01, 0x02}) // < 8
}

// TestDispatchRelay_DestInPeerMesh covers the peerMap-hit branch in
// the dispatch pre-check (peer mesh tier-2 fallback).
func TestDispatchRelay_DestInPeerMesh(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(1, nil)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	// Seed the peer mesh with destID=42 so the pre-check passes
	// without an entry in the local nodes map.
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	pm := map[uint32]*net.UDPAddr{42: peer}
	s.peerNodes.Store(&pm)

	data := make([]byte, 12)
	binary.BigEndian.PutUint32(data[0:4], 1)
	binary.BigEndian.PutUint32(data[4:8], 42)
	data[8], data[9], data[10], data[11] = 'X', 'Y', 'Z', '!'
	s.dispatchRelay(data)
}

// TestRelayStatsLoop_ClosesOnDone exercises the s.done branch of
// relayStatsLoop by closing the server and letting the goroutine
// exit. The 60-second ticker would otherwise never fire in a test.
func TestRelayStatsLoop_ClosesOnDone(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()

	// Bump a counter so any tick (if one fired) would log; this also
	// exercises the atomic load path inside the loop.
	s.relayForwarded.Add(7)
	s.relayDropped.Add(1)
	s.relayNotFound.Add(2)

	// Close: this signals s.done; relayStatsLoop's select picks the
	// done branch and exits cleanly. Without -race timing pressure
	// this would otherwise just sit on the 60s ticker.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestNodeMap_Snapshot_RaceFreeUnderUpsert hammers the same nodeID
// from many goroutines while Snapshot reads it — proves the lock
// covers the addr-pointer read (the regression that prompted the
// Snapshot() refactor on 2026-05-19).
func TestNodeMap_Snapshot_RaceFreeUnderUpsert(t *testing.T) {
	t.Parallel()
	m := newNodeMap()
	addr1 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	addr2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2}
	m.Upsert(99, addr1, time.Now(), 0)

	stop := make(chan struct{})
	defer close(stop)

	// Writer goroutine flips the addr.
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				m.Upsert(99, addr1, time.Now(), 0)
				m.Upsert(99, addr2, time.Now(), 0)
			}
		}
	}()

	// Many reader goroutines read concurrently. With -race, an
	// unprotected read of beaconNode.addr would flag here.
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 1000; j++ {
				if _, ok := m.Snapshot(99); !ok {
					done <- struct{}{}
					return
				}
				_ = m.Get(99)
				_ = m.Has(99)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// TestNodeMap_ShardDistribution proves the shard hash spreads
// sequential nodeIDs across all 64 shards (no shard is empty when
// the input range covers more than nodeShardCount entries).
func TestNodeMap_ShardDistribution(t *testing.T) {
	t.Parallel()
	m := newNodeMap()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	// Insert 64 IDs that each map to a distinct shard (i & 63 = i).
	for i := uint32(0); i < nodeShardCount; i++ {
		m.Upsert(i, addr, time.Now(), maxBeaconNodes)
	}
	for i := 0; i < nodeShardCount; i++ {
		m.shards[i].mu.RLock()
		empty := len(m.shards[i].nodes) == 0
		m.shards[i].mu.RUnlock()
		if empty {
			t.Errorf("shard %d empty after inserting all 0..%d", i, nodeShardCount-1)
		}
	}
}

// TestHandlePunchRequest_UnknownTarget covers the early-return when
// the target node is not registered. Pre-registers the requester so
// only the target lookup misses.
func TestHandlePunchRequest_UnknownTarget(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 100) // requester
	binary.BigEndian.PutUint32(data[4:8], 999) // target — never registered

	s.handlePunchRequest(data, addr)

	// Requester should have been upserted as a side effect, even when
	// the target is missing — that's the documented behaviour of
	// handlePunchRequest (helps symmetric-NAT port refresh).
	if !s.nodes.Has(100) {
		t.Error("requester not upserted on punch-with-missing-target")
	}
}

// TestHandleSync_ExpectedLengthMismatch exercises the
// "claimed nodeCount but message is too short" branch.
func TestHandleSync_ExpectedLengthMismatch(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(1, nil)
	defer s.Close()

	// data = [beaconID(4)][count=10 nodes(2)][... only 4 bytes of nodes]
	data := make([]byte, 6+4)
	binary.BigEndian.PutUint32(data[0:4], 99)
	binary.BigEndian.PutUint16(data[4:6], 10) // claim 10 nodes
	// only 4 bytes of node data follows — expected = 6 + 40 = 46
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	s.handleSync(data, addr)

	// No peers added because the message was rejected.
	if got := s.PeerNodeCount(); got != 0 {
		t.Errorf("PeerNodeCount = %d, want 0 (msg rejected)", got)
	}
}

// TestHandleSync_OverwritesPreviousPeerNodes pins that a second
// gossip from the same peer replaces (not merges) the prior entries.
func TestHandleSync_OverwritesPreviousPeerNodes(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(1, nil)
	defer s.Close()

	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}
	// First gossip: 3 nodes
	first := make([]byte, 6+12)
	binary.BigEndian.PutUint32(first[0:4], 2)
	binary.BigEndian.PutUint16(first[4:6], 3)
	binary.BigEndian.PutUint32(first[6:10], 100)
	binary.BigEndian.PutUint32(first[10:14], 200)
	binary.BigEndian.PutUint32(first[14:18], 300)
	s.handleSync(first, peer)
	if got := s.PeerNodeCount(); got != 3 {
		t.Fatalf("after first: PeerNodeCount = %d, want 3", got)
	}

	// Second gossip from same peer: 1 node only
	second := make([]byte, 6+4)
	binary.BigEndian.PutUint32(second[0:4], 2)
	binary.BigEndian.PutUint16(second[4:6], 1)
	binary.BigEndian.PutUint32(second[6:10], 400)
	s.handleSync(second, peer)

	// The COW logic keeps only entries not from this peer, then adds
	// the new ones. From this peer's perspective the old 3 are gone.
	if got := s.PeerNodeCount(); got != 1 {
		t.Errorf("after second: PeerNodeCount = %d, want 1 (old 3 replaced)", got)
	}
}
