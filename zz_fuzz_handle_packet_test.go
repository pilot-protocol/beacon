// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon_test

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/beacon"
)

// FuzzBeaconHandlePacket pushes arbitrary UDP datagrams into a real
// beacon server and asserts the read goroutine never panics. The
// previous file zz_fuzz_beacon_test.go was named "fuzz" but only
// contained unit tests — this is the actual Go fuzz target.
//
// The server's read loop catches len(data)==0 explicitly; for any
// other shape the dispatch flows into handleDiscover/handlePunchRequest/
// dispatchRelay/handleSync. Each parser has its own length guards;
// a fuzz find here would be either a panic that crashes the daemon
// goroutine (no test signal would surface — instead the server
// would just stop responding), or a malformed input that drives an
// internal panic before the deferred recover (if any).
//
// Throughput is limited by UDP I/O (~10k execs/sec), but ~300k execs
// over 30s is enough to cover all four message types with random
// adjacent bytes.
func FuzzBeaconHandlePacket(f *testing.F) {
	// Seed: minimal known-good messages for each type.
	{
		// Discover
		msg := make([]byte, 5)
		msg[0] = protocol.BeaconMsgDiscover
		binary.BigEndian.PutUint32(msg[1:], 42)
		f.Add(msg)
	}
	{
		// PunchRequest
		msg := make([]byte, 9)
		msg[0] = protocol.BeaconMsgPunchRequest
		binary.BigEndian.PutUint32(msg[1:], 100)
		binary.BigEndian.PutUint32(msg[5:], 200)
		f.Add(msg)
	}
	{
		// Relay with small payload
		payload := []byte("hello")
		msg := make([]byte, 9+len(payload))
		msg[0] = protocol.BeaconMsgRelay
		binary.BigEndian.PutUint32(msg[1:], 1)
		binary.BigEndian.PutUint32(msg[5:], 2)
		copy(msg[9:], payload)
		f.Add(msg)
	}
	{
		// Sync with 2 nodes
		msg := make([]byte, 1+4+2+8)
		msg[0] = protocol.BeaconMsgSync
		binary.BigEndian.PutUint32(msg[1:5], 99)
		binary.BigEndian.PutUint16(msg[5:7], 2)
		binary.BigEndian.PutUint32(msg[7:], 100)
		binary.BigEndian.PutUint32(msg[11:], 200)
		f.Add(msg)
	}
	// Single-byte messages for each known type.
	f.Add([]byte{protocol.BeaconMsgDiscover})
	f.Add([]byte{protocol.BeaconMsgPunchRequest})
	f.Add([]byte{protocol.BeaconMsgRelay})
	f.Add([]byte{protocol.BeaconMsgSync})
	f.Add([]byte{0xFF}) // unknown type
	// One byte under each minimum-length guard.
	f.Add([]byte{protocol.BeaconMsgDiscover, 0x00, 0x00, 0x00})
	f.Add([]byte{protocol.BeaconMsgPunchRequest, 0x01, 0x02, 0x03})
	// Sync with claimed-count larger than actual body — truncation case.
	{
		msg := make([]byte, 1+4+2+8)
		msg[0] = protocol.BeaconMsgSync
		binary.BigEndian.PutUint32(msg[1:5], 1)
		binary.BigEndian.PutUint16(msg[5:7], 0xFFFF) // claim 65535
		f.Add(msg)
	}

	// Start a single beacon server for the whole fuzz run. Spinning a
	// server per iteration would cap throughput at ~50/sec — sharing a
	// long-lived one keeps the read goroutine hot and stresses the
	// dispatch path under concurrent inputs.
	srv := beacon.New()
	go srv.ListenAndServe("127.0.0.1:0")
	select {
	case <-srv.Ready():
	case <-time.After(2 * time.Second):
		f.Fatal("beacon did not start")
	}
	defer srv.Close()
	addr := srv.Addr().(*net.UDPAddr)

	// Shared client conn pool: reusing connections cuts syscall overhead
	// roughly 3x vs DialUDP per iteration.
	var connMu sync.Mutex
	conns := make([]*net.UDPConn, 0, 8)
	getConn := func() *net.UDPConn {
		connMu.Lock()
		defer connMu.Unlock()
		if len(conns) > 0 {
			c := conns[len(conns)-1]
			conns = conns[:len(conns)-1]
			return c
		}
		c, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return nil
		}
		return c
	}
	putConn := func(c *net.UDPConn) {
		connMu.Lock()
		defer connMu.Unlock()
		if len(conns) < 16 {
			conns = append(conns, c)
		} else {
			c.Close()
		}
	}
	defer func() {
		connMu.Lock()
		for _, c := range conns {
			c.Close()
		}
		connMu.Unlock()
	}()

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		// UDP datagrams above MTU may be silently dropped; cap to keep
		// the fuzzer focused on parser logic, not fragmentation.
		if len(data) > 1400 {
			data = data[:1400]
		}
		c := getConn()
		if c == nil {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := c.Write(data)
		if err != nil {
			c.Close()
			return
		}
		// We don't necessarily expect a reply — discover replies, sync
		// does not, relay forwards. Drain anything with a short
		// deadline so the next iteration starts clean.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		buf := make([]byte, 1500)
		for {
			_, err := c.Read(buf)
			if err != nil {
				break
			}
		}
		putConn(c)
	})
}
