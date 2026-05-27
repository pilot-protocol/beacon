// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"net"
	"testing"
)

// TestHandlePacketEmptyDoesNotPanic pins the P1 DoS fix: handlePacket
// must not panic on a zero-length data slice.
//
// Before the fix: beacon/server.go:444 did `msgType := data[0]` with
// no length guard. The UDP readLoop checks `m.N < 1` before dispatch,
// but the WSS OnFrame path (beacon/wss/server.go:445) only enforces
// an UPPER bound on body length. An authenticated WSS peer sending a
// 0-byte binary frame crashed the entire beacon process.
func TestHandlePacketEmptyDoesNotPanic(t *testing.T) {
	t.Parallel()
	s := &Server{}
	// We use a deliberately-zero-init Server because we only care about
	// the empty-slice guard at the very top of handlePacket — nothing
	// after the guard is reachable on this input.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BUG: handlePacket(nil, _) panicked: %v", r)
		}
	}()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	s.handlePacket(nil, addr)
	s.handlePacket([]byte{}, addr)
}
