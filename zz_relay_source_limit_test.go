// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// relayFrame builds a bare relay body (the bytes dispatchRelay parses,
// i.e. everything after the message-type byte).
func relayFrame(senderID, destID uint32, payload string) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(b[0:4], senderID)
	binary.BigEndian.PutUint32(b[4:8], destID)
	copy(b[8:], payload)
	return b
}

func drainRelayCh(s *Server) int {
	n := 0
	for {
		select {
		case job := <-s.relayCh:
			s.returnPayload(job.payload)
			n++
		default:
			return n
		}
	}
}

// TestRelayBudgetIsPerDatagramSource pins that the relay budget is
// charged against the observed datagram source, not the sender id
// carried in the frame body. One source that varies the sender id on
// every packet must still be held to the single per-source budget.
func TestRelayBudgetIsPerDatagramSource(t *testing.T) {
	t.Parallel()
	s := New()
	defer s.Close()

	dest := uint32(4242)
	s.nodes.Upsert(dest, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, time.Now(), maxBeaconNodes)

	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 40000}

	// Three times the per-source budget, every packet claiming a
	// different sender id.
	const attempts = maxRelaysPerSourcePerSecond * 3
	for i := 0; i < attempts; i++ {
		s.dispatchRelay(relayFrame(uint32(i+1), dest, "x"), relaySourceForUDP(src))
	}

	got := drainRelayCh(s)
	if got > maxRelaysPerSourcePerSecond {
		t.Fatalf("one datagram source enqueued %d relays with rotating sender ids; budget is %d per second",
			got, maxRelaysPerSourcePerSecond)
	}
	if got == 0 {
		t.Fatalf("no relays enqueued at all; the limiter rejected everything")
	}
}

// TestRelayBudgetIsIndependentPerSource is the companion property: two
// distinct datagram sources must not share one budget.
func TestRelayBudgetIsIndependentPerSource(t *testing.T) {
	t.Parallel()
	s := New()
	defer s.Close()

	dest := uint32(4243)
	s.nodes.Upsert(dest, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, time.Now(), maxBeaconNodes)

	a := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1111}
	b := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 2222}

	// Exhaust a's budget entirely, then send one packet from b.
	for i := 0; i < maxRelaysPerSourcePerSecond+50; i++ {
		s.dispatchRelay(relayFrame(1, dest, "x"), relaySourceForUDP(a))
	}
	before := drainRelayCh(s)
	if before == 0 {
		t.Fatal("source a enqueued nothing")
	}

	s.dispatchRelay(relayFrame(1, dest, "y"), relaySourceForUDP(b))
	if n := drainRelayCh(s); n != 1 {
		t.Fatalf("source b enqueued %d relays after source a exhausted its budget; want 1", n)
	}
}

// TestRelaySourceKeyDistinguishesEndpoints checks the key construction
// itself: same address different port, different address same port, and
// the bridged form must all be distinct, and the IPv4 / IPv4-in-IPv6
// spellings of one address must be equal.
func TestRelaySourceKeyDistinguishesEndpoints(t *testing.T) {
	t.Parallel()

	v4 := relaySourceForUDP(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 5).To4(), Port: 9001})
	v4b := relaySourceForUDP(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 5).To16(), Port: 9001})
	if v4 != v4b {
		t.Error("the 4-byte and 16-byte spellings of one address produced different keys")
	}

	otherPort := relaySourceForUDP(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 5).To4(), Port: 9002})
	if v4 == otherPort {
		t.Error("two ports on one address produced the same key")
	}

	otherIP := relaySourceForUDP(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 6).To4(), Port: 9001})
	if v4 == otherIP {
		t.Error("two addresses on one port produced the same key")
	}

	bridged := relaySourceForBridge(7)
	if bridged == v4 || bridged == relaySourceForBridge(8) {
		t.Error("bridged keys collided")
	}
	if relaySourceForUDP(nil) != (relaySourceKey{}) {
		t.Error("a nil address should produce the zero key, not panic or vary")
	}
}

// TestRelayBudgetForBridgedFramesUsesPeerID pins that frames handed over
// by the compat WSS bridge are budgeted per authenticated peer — every
// bridged frame shares one synthetic datagram address, so keying on that
// address would put the whole bridge on a single budget.
func TestRelayBudgetForBridgedFramesUsesPeerID(t *testing.T) {
	t.Parallel()
	s := New()
	defer s.Close()

	dest := uint32(4244)
	s.nodes.Upsert(dest, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, time.Now(), maxBeaconNodes)

	for i := 0; i < maxRelaysPerSourcePerSecond+50; i++ {
		s.dispatchRelay(relayFrame(999, dest, "x"), relaySourceForBridge(1001))
	}
	if drainRelayCh(s) == 0 {
		t.Fatal("bridged peer 1001 enqueued nothing")
	}

	s.dispatchRelay(relayFrame(999, dest, "y"), relaySourceForBridge(1002))
	if n := drainRelayCh(s); n != 1 {
		t.Fatalf("bridged peer 1002 enqueued %d relays after peer 1001 exhausted its budget; want 1", n)
	}
}
