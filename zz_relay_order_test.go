// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// The packets of one relayed flow must leave the beacon in the order they
// arrived. The relay workers used to share one queue and batch separately, so
// consecutive packets left in different batches, out of order; a stream
// receiver reports each early arrival, and three reports make the sender
// retransmit and halve its window with nothing actually lost.
func TestRelayKeepsAFlowsPacketsInOrder(t *testing.T) {
	t.Parallel()
	s, addr := startTestBeacon(t)
	defer s.Close()

	const senderID, destID = 4101, 4102

	dest, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial dest: %v", err)
	}
	defer dest.Close()
	discover := make([]byte, 5)
	discover[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(discover[1:], destID)
	if _, err := dest.Write(discover); err != nil {
		t.Fatalf("discover: %v", err)
	}
	// The discover reply; after it, everything on this socket is a delivery.
	dest.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	if _, err := dest.Read(buf); err != nil {
		t.Fatalf("discover reply: %v", err)
	}

	sender, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial sender: %v", err)
	}
	defer sender.Close()

	// Well under the per-source limit, in bursts short enough that the
	// loopback socket buffers hold them.
	const packets = 600
	go func() {
		msg := make([]byte, 9+4)
		msg[0] = protocol.BeaconMsgRelay
		binary.BigEndian.PutUint32(msg[1:], senderID)
		binary.BigEndian.PutUint32(msg[5:], destID)
		for i := 0; i < packets; i++ {
			binary.BigEndian.PutUint32(msg[9:], uint32(i))
			sender.Write(msg)
			if i%50 == 49 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	got, outOfOrder, last := 0, 0, -1
	for got < packets {
		dest.SetReadDeadline(time.Now().Add(time.Second))
		n, err := dest.Read(buf)
		if err != nil {
			break // whatever is left was dropped on loopback; ordering is what is under test
		}
		if n != 1+4+4 || buf[0] != protocol.BeaconMsgRelayDeliver {
			continue
		}
		seq := int(binary.BigEndian.Uint32(buf[5:9]))
		if seq < last {
			outOfOrder++
		} else {
			last = seq
		}
		got++
	}
	if got < packets*9/10 {
		t.Fatalf("only %d of %d relayed packets arrived", got, packets)
	}
	if outOfOrder != 0 {
		t.Fatalf("%d of %d relayed packets arrived after a later one", outOfOrder, got)
	}
}
