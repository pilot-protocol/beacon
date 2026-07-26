// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// syncBody builds a gossip sync body (everything after the message-type
// byte) advertising the given node ids on behalf of peerBeaconID.
func syncBody(peerBeaconID uint32, nodeIDs ...uint32) []byte {
	b := make([]byte, 6+4*len(nodeIDs))
	binary.BigEndian.PutUint32(b[0:4], peerBeaconID)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(nodeIDs)))
	for i, id := range nodeIDs {
		binary.BigEndian.PutUint32(b[6+4*i:10+4*i], id)
	}
	return b
}

func peerRoute(s *Server, nodeID uint32) *net.UDPAddr {
	return (*s.peerNodes.Load())[nodeID]
}

// TestStrictGossipRejectsSourceOutsidePeerSet pins the peer-set gate: a
// sync from an address that is not a known peer beacon must not install
// routes into the peer mesh the relay workers read.
func TestStrictGossipRejectsSourceOutsidePeerSet(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(1, []string{"198.51.100.7:9001"})
	defer s.Close()
	s.SetStrictGossip(true)
	if !s.StrictGossip() {
		t.Fatal("SetStrictGossip(true) did not take effect")
	}

	outsider := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 66), Port: 9001}
	s.handleSync(syncBody(2, 500, 501), outsider)

	if got := peerRoute(s, 500); got != nil {
		t.Fatalf("gossip from %s installed a route for node 500 -> %s; want no route", outsider, got)
	}

	// The configured peer is accepted on the same code path, so the gate
	// rejects on provenance and not by refusing all gossip.
	known := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 9001}
	s.handleSync(syncBody(2, 500, 501), known)
	if got := peerRoute(s, 500); got == nil {
		t.Fatal("gossip from the configured peer was rejected; want the route installed")
	}
}

// TestStrictGossipDefaultsOff pins that the gate is opt-in, so existing
// deployments keep converging until an operator turns it on.
func TestStrictGossipDefaultsOff(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(1, nil)
	defer s.Close()

	if s.StrictGossip() {
		t.Fatal("strict gossip is on by default; it must be opt-in")
	}
	outsider := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 67), Port: 9001}
	s.handleSync(syncBody(2, 600), outsider)
	if peerRoute(s, 600) == nil {
		t.Fatal("with the gate off, gossip from any source should still install routes")
	}
}

// TestStrictGossipMatchesPeerOnAddressNotPort covers a peer whose gossip
// egresses from a rewritten source port.
func TestStrictGossipMatchesPeerOnAddressNotPort(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(1, []string{"198.51.100.8:9001"})
	defer s.Close()
	s.SetStrictGossip(true)

	remapped := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 8), Port: 34567}
	s.handleSync(syncBody(2, 700), remapped)
	if peerRoute(s, 700) == nil {
		t.Fatal("gossip from a known peer address on a rewritten port was rejected")
	}
}

// TestStaleGossipRoutesExpire pins that routes published by a beacon
// that stops gossiping are withdrawn, instead of standing forever and
// pointing relay traffic at a beacon that is gone.
func TestStaleGossipRoutesExpire(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(1, nil)
	defer s.Close()

	gone := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 9001}
	live := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 11), Port: 9001}
	s.handleSync(syncBody(2, 800), gone)
	s.handleSync(syncBody(3, 801), live)

	if peerRoute(s, 800) == nil || peerRoute(s, 801) == nil {
		t.Fatal("setup: both gossip sources should have installed routes")
	}

	// Age out only the first source, then sweep.
	s.peerWriteMu.Lock()
	s.gossipSeen[gone.String()] = time.Now().Add(-2 * gossipPeerTTL)
	s.peerWriteMu.Unlock()
	s.sweepStaleGossip(time.Now().Add(-gossipPeerTTL))

	if got := peerRoute(s, 800); got != nil {
		t.Errorf("route for node 800 survived its source going silent: %s", got)
	}
	if peerRoute(s, 801) == nil {
		t.Error("route for node 801 was withdrawn even though its source is still gossiping")
	}
}
