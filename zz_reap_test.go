// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"net"
	"testing"
	"time"
)

func TestReapStaleNodes_Empty(t *testing.T) {
	t.Parallel()
	s := New()
	// No nodes — reap is a no-op.
	s.reapStaleNodes()
	if s.nodes.Len() != 0 {
		t.Errorf("Len = %d, want 0", s.nodes.Len())
	}
}

func TestReapStaleNodes_RemovesOldEntries(t *testing.T) {
	t.Parallel()
	s := New()
	now := time.Now()
	old := now.Add(-2 * beaconNodeTTL) // 2× past TTL
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}

	s.nodes.Upsert(1, addr, old, maxBeaconNodes)
	s.nodes.Upsert(2, addr, now, maxBeaconNodes)
	if got := s.nodes.Len(); got != 2 {
		t.Fatalf("pre: Len = %d, want 2", got)
	}

	s.reapStaleNodes()

	if got := s.nodes.Len(); got != 1 {
		t.Errorf("post: Len = %d, want 1 (old reaped)", got)
	}
	if !s.nodes.Has(2) {
		t.Error("fresh node 2 should still be present")
	}
	if s.nodes.Has(1) {
		t.Error("stale node 1 should be reaped")
	}
}

func TestNodeMap_HasAndSnapshot(t *testing.T) {
	t.Parallel()
	s := New()
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4000}
	s.nodes.Upsert(7, addr, time.Now(), maxBeaconNodes)
	if !s.nodes.Has(7) {
		t.Error("Has(7): want true")
	}
	got, ok := s.nodes.Snapshot(7)
	if !ok || got == nil {
		t.Fatalf("Snapshot(7) = (%v, %v)", got, ok)
	}
	if got.Port != 4000 {
		t.Errorf("Port = %d, want 4000", got.Port)
	}
	// Snapshot returns the underlying *UDPAddr — verified by re-reading
	// after Upsert with a different addr swaps it out.
	addr2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 6), Port: 4001}
	s.nodes.Upsert(7, addr2, time.Now(), maxBeaconNodes)
	got2, _ := s.nodes.Snapshot(7)
	if got2.Port != 4001 {
		t.Errorf("after Upsert: Port = %d, want 4001", got2.Port)
	}
}

func TestNodeMap_GetMissing(t *testing.T) {
	t.Parallel()
	s := New()
	if got := s.nodes.Get(9999); got != nil {
		t.Errorf("Get(missing) = %v, want nil", got)
	}
	if got, ok := s.nodes.Snapshot(9999); ok || got != nil {
		t.Errorf("Snapshot(missing) = (%v, %v)", got, ok)
	}
}

func TestNodeMap_AtCapacity(t *testing.T) {
	t.Parallel()
	s := New()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	// maxTotal is divided by nodeShardCount internally — pick a value
	// large enough that the per-shard cap allows one insert but rejects
	// the next. nodeShardCount=64, so maxTotal=64 → per-shard cap of 1.
	// Use distinct nodeIDs that hash to the same shard via ID itself: 0
	// and 64 both land on shard 0 (64 % 64 == 0).
	inserted, atCap := s.nodes.Upsert(0, addr, time.Now(), 64)
	if !inserted || atCap {
		t.Errorf("first: inserted=%v atCap=%v, want true,false", inserted, atCap)
	}
	_, atCap = s.nodes.Upsert(64, addr, time.Now(), 64)
	if !atCap {
		t.Error("second on same shard: atCap should be true")
	}
}

func TestNodeMap_IDsAndLen(t *testing.T) {
	t.Parallel()
	s := New()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	for i := uint32(1); i <= 5; i++ {
		s.nodes.Upsert(i, addr, time.Now(), maxBeaconNodes)
	}
	if got := s.nodes.Len(); got != 5 {
		t.Errorf("Len = %d, want 5", got)
	}
	if got := len(s.nodes.IDs()); got != 5 {
		t.Errorf("len(IDs()) = %d, want 5", got)
	}
}

func TestNodeMap_UpsertUpdatesAddr(t *testing.T) {
	t.Parallel()
	s := New()
	addr1 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}
	addr2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2}
	s.nodes.Upsert(1, addr1, time.Now(), maxBeaconNodes)
	s.nodes.Upsert(1, addr2, time.Now(), maxBeaconNodes)
	// Single entry — second Upsert replaced addr.
	if got := s.nodes.Len(); got != 1 {
		t.Errorf("Len = %d, want 1", got)
	}
	snap, _ := s.nodes.Snapshot(1)
	if snap.Port != 2 {
		t.Errorf("Port = %d, want 2 (updated)", snap.Port)
	}
}
