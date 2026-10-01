// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestNotifyNode: a registered node receives the two-byte notify — nothing
// else — at most once per notifyMinInterval; an unknown node is an error.
func TestNotifyNode(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	if err := s.NotifyNode(99999); !errors.Is(err, protocol.ErrNodeNotFound) {
		t.Fatalf("unknown node: err = %v, want ErrNodeNotFound", err)
	}

	node, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	s.nodes.Upsert(7, node.LocalAddr().(*net.UDPAddr), time.Now(), maxBeaconNodes)

	for i := 0; i < 20; i++ {
		if err := s.NotifyNode(7); err != nil {
			t.Fatalf("NotifyNode: %v", err)
		}
	}
	buf := make([]byte, 64)
	_ = node.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := node.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no notify received: %v", err)
	}
	if n != 2 || buf[0] != MsgNotify || buf[1] != NotifyKindHandshake {
		t.Fatalf("notify = %x, want [%02x %02x]", buf[:n], MsgNotify, NotifyKindHandshake)
	}
	_ = node.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := node.ReadFromUDP(buf); err == nil {
		t.Fatalf("a second notify (%x) arrived within %s of the first", buf[:n], notifyMinInterval)
	}

	// After the interval the next one goes out.
	s.nodes.shardFor(7).nodes[7].lastNotify = time.Now().Add(-notifyMinInterval)
	if err := s.NotifyNode(7); err != nil {
		t.Fatalf("NotifyNode: %v", err)
	}
	_ = node.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := node.ReadFromUDP(buf); err != nil {
		t.Fatalf("no notify after the interval: %v", err)
	}
}
