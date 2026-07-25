// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"crypto/ed25519"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// The sibling zz_fuzz_handle_packet_test.go target drives the beacon over a
// real UDP socket. That exercises the full receive path but caps throughput
// at UDP I/O speed and, more importantly, cannot attribute a panic to the
// input that caused it — the panic unwinds the server's own read goroutine,
// not the fuzz goroutine. The targets below call the dispatch functions
// directly on the fuzzer's goroutine so a crash is both fast to find and
// reproducible from the recorded corpus entry.
//
// They deliberately bypass Server.handlePacket's own recover shim where the
// sub-handler is called directly, so a missing bounds check surfaces as a
// test failure rather than being swallowed.

// fuzzServer builds a Server with a real bound socket but no read loop, so
// the fuzzer owns dispatch scheduling. Binding matters: the discover and
// punch handlers write replies through s.conn, and a nil socket would take
// those code paths out of reach.
func fuzzServer(tb testing.TB) *Server {
	tb.Helper()
	s := NewWithPeers(1, nil)
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("bind: %v", err)
	}
	s.conn = c
	s.conns = []*net.UDPConn{c}
	tb.Cleanup(func() {
		close(s.done)
		c.Close()
	})
	return s
}

// fuzzAddr is the synthetic remote used for every iteration. A stable
// address keeps the per-source rate limiters in a steady state rather than
// growing an entry per iteration.
var fuzzAddr = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 41234}

func seedBeaconCorpus(f *testing.F) {
	f.Helper()

	// Well-formed message of each type.
	discover := make([]byte, 5)
	discover[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(discover[1:], 42)
	f.Add(discover)

	discoverEx := make([]byte, 5+ed25519.PublicKeySize)
	discoverEx[0] = protocol.BeaconMsgDiscoverEx
	binary.BigEndian.PutUint32(discoverEx[1:5], 42)
	f.Add(discoverEx)

	punch := make([]byte, 9)
	punch[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(punch[1:5], 100)
	binary.BigEndian.PutUint32(punch[5:9], 200)
	f.Add(punch)

	relay := make([]byte, 9+16)
	relay[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(relay[1:5], 1)
	binary.BigEndian.PutUint32(relay[5:9], 2)
	f.Add(relay)

	sync := make([]byte, 1+4+2+8)
	sync[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(sync[1:5], 99)
	binary.BigEndian.PutUint16(sync[5:7], 2)
	f.Add(sync)

	// Adversarial shapes: empty, single byte per type, one byte under every
	// length guard, and counters that claim far more body than is present.
	f.Add([]byte{})
	for _, t := range []byte{
		protocol.BeaconMsgDiscover,
		protocol.BeaconMsgDiscoverEx,
		protocol.BeaconMsgPunchRequest,
		protocol.BeaconMsgRelay,
		protocol.BeaconMsgSync,
		0x00, 0x0F, 0xFF,
	} {
		f.Add([]byte{t})
		f.Add([]byte{t, 0x00})
		f.Add([]byte{t, 0xFF, 0xFF, 0xFF})
		f.Add([]byte{t, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	}

	// Sync claiming the maximum node count with an empty body — the
	// length-validation branch.
	truncSync := make([]byte, 1+4+2)
	truncSync[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint16(truncSync[5:7], 0xFFFF)
	f.Add(truncSync)

	// Sync claiming a count one node larger than the body carries.
	offByOne := make([]byte, 1+4+2+4)
	offByOne[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint16(offByOne[5:7], 2)
	f.Add(offByOne)

	// Relay with a payload right at the maxRelayPayload boundary is too
	// large to keep in the corpus; use a small one plus a header-only frame.
	f.Add([]byte{protocol.BeaconMsgRelay, 0, 0, 0, 1, 0, 0, 0, 2})

	// Punch request carrying a truncated grant trailer (expiry + signature).
	shortGrant := make([]byte, 9+punchGrantTrailerSize-1)
	shortGrant[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(shortGrant[1:5], 100)
	binary.BigEndian.PutUint32(shortGrant[5:9], 200)
	f.Add(shortGrant)
}

// FuzzBeaconDispatch drives arbitrary bytes through the full type-dispatch
// switch — the exact bytes an unauthenticated UDP source (or a compat-mode
// WSS peer, via EnableCompatWSS's OnFrame) can put on the wire.
func FuzzBeaconDispatch(f *testing.F) {
	seedBeaconCorpus(f)
	s := fuzzServer(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxRelayPayload {
			data = data[:maxRelayPayload]
		}
		// handlePacket recovers internally, so a panic would otherwise be
		// swallowed. Compare the counter across the call to surface it.
		before := RecoveredPanicCount()
		s.handlePacket(data, fuzzAddr)
		if after := RecoveredPanicCount(); after != before {
			t.Fatalf("handlePacket recovered a panic on input %x", data)
		}
	})
}

// FuzzBeaconHandleDiscover targets the discover parser directly (no recover
// shim in the way). Covers the variable-length pubkey trailer, the
// per-nodeID endpoint rate limiter, and the reply encoder.
func FuzzBeaconHandleDiscover(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add(make([]byte, 4))
	f.Add(make([]byte, 4+ed25519.PublicKeySize))
	f.Add(make([]byte, 4+ed25519.PublicKeySize-1))
	f.Add(make([]byte, 4+ed25519.PublicKeySize+1))

	s := fuzzServer(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			data = data[:4096]
		}
		// wantDest toggles the dstNodes bookkeeping branch.
		s.handleDiscover(data, fuzzAddr, false)
		s.handleDiscover(data, fuzzAddr, true)
		// An IPv6 remote drives the 16-byte reply-encoding branch.
		s.handleDiscover(data, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5}, false)
	})
}

// FuzzBeaconHandleSync targets the gossip parser. The claimed node count is
// a wire-controlled uint16 used to size an allocation and to index into the
// body — the classic length-prefix mismatch shape.
func FuzzBeaconHandleSync(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 5))
	f.Add(make([]byte, 6))
	{
		b := make([]byte, 6)
		binary.BigEndian.PutUint16(b[4:6], 0xFFFF)
		f.Add(b)
	}
	{
		b := make([]byte, 6+4*3)
		binary.BigEndian.PutUint16(b[4:6], 3)
		f.Add(b)
	}
	{
		// Count larger than body by exactly one node.
		b := make([]byte, 6+4*2)
		binary.BigEndian.PutUint16(b[4:6], 3)
		f.Add(b)
	}

	s := fuzzServer(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			data = data[:65535]
		}
		s.handleSync(data, fuzzAddr)
	})
}

// FuzzBeaconDispatchRelay targets the relay header parser and the pooled
// payload copy. The destination is pre-registered so the fuzzer gets past
// the not-found pre-check and into the enqueue path.
func FuzzBeaconDispatchRelay(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 7))
	f.Add(make([]byte, 8))
	{
		b := make([]byte, 8+32)
		binary.BigEndian.PutUint32(b[0:4], 1)
		binary.BigEndian.PutUint32(b[4:8], 7777)
		f.Add(b)
	}

	s := fuzzServer(f)
	// Register the destination so the tier-1 pre-check passes.
	s.nodes.Upsert(7777, fuzzAddr, time.Now(), maxBeaconNodes)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxRelayPayload {
			data = data[:maxRelayPayload]
		}
		s.dispatchRelay(data)
		// Drain so the buffered channel cannot fill across iterations.
		for {
			select {
			case job := <-s.relayCh:
				s.returnPayload(job.payload)
				continue
			default:
			}
			break
		}
	})
}

// FuzzBeaconPunchGrant targets the punch-grant trailer parser with the
// token requirement enabled. The signed-grant path slices a fixed-size
// expiry + signature out of caller-supplied bytes and hands the signature
// to ed25519.Verify against a key pulled from the nodePubKeys map, so it
// combines a bounds check with a key-length-sensitive verify.
func FuzzBeaconPunchGrant(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 8))
	f.Add(make([]byte, punchGrantTrailerSize-1))
	f.Add(make([]byte, punchGrantTrailerSize))
	f.Add(make([]byte, punchGrantTrailerSize+64))
	{
		// Non-expired grant so the ed25519 verify is actually reached.
		b := make([]byte, punchGrantTrailerSize)
		binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().Add(time.Hour).Unix()))
		f.Add(b)
	}

	s := fuzzServer(f)
	s.SetRequirePunchToken(true)

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatalf("keygen: %v", err)
	}
	// A well-formed key for one target and a deliberately wrong-length key
	// for another: the second entry is the shape that made crypto.Verify
	// panic before it grew a length guard.
	s.nodePubKeys.Store(uint32(200), pub)
	s.nodePubKeys.Store(uint32(201), ed25519.PublicKey(make([]byte, 5)))
	s.nodePubKeys.Store(uint32(202), ed25519.PublicKey(nil))

	f.Fuzz(func(t *testing.T, trailer []byte) {
		if len(trailer) > 4096 {
			trailer = trailer[:4096]
		}
		for _, target := range []uint32{200, 201, 202, 203} {
			_ = s.verifyPunchGrant(trailer, 100, target)
		}
	})
}

// FuzzBeaconHandlePunchRequest drives the full punch-request handler,
// including the rate-limit bypass label and the grant trailer.
func FuzzBeaconHandlePunchRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 7))
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 8+punchGrantTrailerSize))

	s := fuzzServer(f)
	// Wildcard whitelist so the global 10/s cap does not short-circuit
	// almost every iteration before the parser runs.
	s.SetPunchWhitelist([]string{"*"})
	s.nodes.Upsert(100, fuzzAddr, time.Now(), maxBeaconNodes)
	s.nodes.Upsert(200, fuzzAddr, time.Now(), maxBeaconNodes)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			data = data[:4096]
		}
		for _, requireToken := range []bool{false, true} {
			s.SetRequirePunchToken(requireToken)
			s.handlePunchRequest(data, fuzzAddr)
		}
	})
}
