// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// Adversarial replay for the forged-Discover endpoint-hijack finding.
//
// BeaconMsgDiscover is unauthenticated by design (it is the STUN-style
// reflexive-address probe), and handleDiscover does two things with the
// attacker-supplied node ID: it upserts nodeID -> observed remote addr,
// and — if the payload carries 32 trailing bytes — it stores nodeID ->
// public key. Neither write proves the sender owns the node ID.
//
// Everything below runs against a local in-process beacon bound to
// 127.0.0.1 on an ephemeral port. Nothing here touches production.

// sendDiscover writes a raw Discover for an arbitrary node ID from the
// caller's socket. Unlike registerNode it does not assume the beacon
// will treat the sender as the owner of that ID — that is the point.
func sendDiscover(t *testing.T, conn *net.UDPConn, nodeID uint32, pub ed25519.PublicKey) {
	t.Helper()
	msg := make([]byte, 5+len(pub))
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], nodeID)
	copy(msg[5:], pub)
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("send discover: %v", err)
	}
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read discover reply: %v", err)
	}
}

func startLocalBeacon(t *testing.T, requirePunchToken bool) (*Server, *net.UDPAddr) {
	t.Helper()
	s := New()
	s.SetRequirePunchToken(requirePunchToken)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	t.Cleanup(func() { s.Close() })
	return s, beaconUDPAddr(t, s)
}

func mappedAddr(t *testing.T, s *Server, nodeID uint32) *net.UDPAddr {
	t.Helper()
	addr, ok := s.nodes.Snapshot(nodeID)
	if !ok {
		return nil
	}
	return addr
}

// TestAttackReplay_DiscoverPreemptiveNodeIDClaim proves the base
// primitive: any UDP source can claim any unregistered node ID and the
// beacon maps that ID to the attacker's endpoint. This is the forged
// Discover from the pentest, replayed against a local beacon.
//
// The flag argument matters: SetRequirePunchToken gates handlePunchRequest
// only, so the claim lands identically with the flag off and on. Both are
// asserted so the test documents exactly what WS3 does not cover.
func TestAttackReplay_DiscoverPreemptiveNodeIDClaim(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name              string
		requirePunchToken bool
	}{
		{"punch_token_off", false},
		{"punch_token_on", true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, beaconAddr := startLocalBeacon(t, tc.requirePunchToken)

			const victimID = uint32(770001)

			attacker, err := net.DialUDP("udp", nil, beaconAddr)
			if err != nil {
				t.Fatalf("dial beacon: %v", err)
			}
			defer attacker.Close()
			attackerAddr := attacker.LocalAddr().(*net.UDPAddr)

			sendDiscover(t, attacker, victimID, nil)

			got := mappedAddr(t, s, victimID)
			if got == nil {
				t.Fatalf("victim node ID was never mapped — test setup is wrong")
			}
			if got.Port == attackerAddr.Port {
				t.Logf("HIJACK LANDED (require_punch_token=%v): node %d maps to attacker %v",
					tc.requirePunchToken, victimID, got)
			} else {
				t.Fatalf("unexpected mapping for node %d: %v (attacker was %v)", victimID, got, attackerAddr)
			}
		})
	}
}

// TestAttackReplay_DiscoverRateLimitBlocksImmediateTakeover is the
// honest counterpart: once a node ID has an endpoint, the per-nodeID
// discover rate limit (discoverMinInterval, 30s) suppresses the Upsert,
// so an attacker cannot instantly steal a *live* mapping. The limiter is
// a throttle, not an authentication check — it delays the takeover by
// one interval, it does not prevent it — but the immediate steal is
// blocked and that is worth pinning.
func TestAttackReplay_DiscoverRateLimitBlocksImmediateTakeover(t *testing.T) {
	t.Parallel()
	s, beaconAddr := startLocalBeacon(t, false)

	const victimID = uint32(770002)

	victim := registerNode(t, beaconAddr, victimID)
	defer victim.Close()
	victimAddr := victim.LocalAddr().(*net.UDPAddr)

	attacker, err := net.DialUDP("udp", nil, beaconAddr)
	if err != nil {
		t.Fatalf("dial beacon: %v", err)
	}
	defer attacker.Close()
	attackerAddr := attacker.LocalAddr().(*net.UDPAddr)

	sendDiscover(t, attacker, victimID, nil)

	got := mappedAddr(t, s, victimID)
	if got == nil {
		t.Fatal("victim mapping vanished")
	}
	if got.Port == attackerAddr.Port {
		t.Fatalf("ATTACK SUCCEEDED: live endpoint for node %d stolen inside the rate-limit window (now %v)", victimID, got)
	}
	if got.Port != victimAddr.Port {
		t.Fatalf("unexpected mapping for node %d: %v (victim was %v)", victimID, got, victimAddr)
	}
	t.Logf("immediate takeover throttled by discoverMinInterval=%v; node %d still maps to the victim %v",
		discoverMinInterval, victimID, got)
}

// TestAttackReplay_DiscoverPubKeyOverwrite pins the fix for the
// key-rebind primitive: the Discover key binding is first-write-wins, so
// a later forged Discover claiming an existing node ID with a different
// key is dropped and the beacon keeps the key it first saw.
func TestAttackReplay_DiscoverPubKeyOverwrite(t *testing.T) {
	t.Parallel()
	s, beaconAddr := startLocalBeacon(t, true)

	const victimID = uint32(770003)

	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate victim key: %v", err)
	}
	victim := registerNodeWithPubKey(t, beaconAddr, victimID, victimPub)
	defer victim.Close()

	attackerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	attacker, err := net.DialUDP("udp", nil, beaconAddr)
	if err != nil {
		t.Fatalf("dial beacon: %v", err)
	}
	defer attacker.Close()

	sendDiscover(t, attacker, victimID, attackerPub)

	v, ok := s.nodePubKeys.Load(victimID)
	if !ok {
		t.Fatal("victim public key vanished")
	}
	stored := v.(ed25519.PublicKey)
	if stored.Equal(attackerPub) {
		t.Fatalf("ATTACK SUCCEEDED: node %d's beacon-held key was rebound to the attacker", victimID)
	}
	if !stored.Equal(victimPub) {
		t.Fatalf("unexpected stored key for node %d", victimID)
	}
	t.Logf("rebind blocked: node %d's beacon-held key still belongs to the victim", victimID)
}

// TestAttackReplay_PunchTokenBypassViaPubKeyRebind chains the two
// primitives end to end against a beacon with require_punch_token=true:
//
//  1. victim registers with its real ed25519 key
//  2. attacker attempts to rebind the beacon's copy of that key via a
//     forged Discover (now dropped by the first-write-wins guard)
//  3. attacker mints a punch grant with their own private key
//  4. beacon verifies the grant against the victim's real key and rejects
//
// The beacon must emit no punch command: the WS3 punch-token control
// holds against a host that can send UDP to the beacon.
func TestAttackReplay_PunchTokenBypassViaPubKeyRebind(t *testing.T) {
	t.Parallel()
	_, beaconAddr := startLocalBeacon(t, true)

	const victimID = uint32(770004)
	const attackerID = uint32(770005)

	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate victim key: %v", err)
	}
	victimConn := registerNodeWithPubKey(t, beaconAddr, victimID, victimPub)
	defer victimConn.Close()
	victimAddr := victimConn.LocalAddr().(*net.UDPAddr)

	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	attackerConn := registerNode(t, beaconAddr, attackerID)
	defer attackerConn.Close()
	attackerAddr := attackerConn.LocalAddr().(*net.UDPAddr)

	// Control, run twice with the same pacing the real attempt uses, so
	// a rejection here cannot be blamed on the punch rate limiter:
	// without the rebind, the grant the attacker can produce is rejected.
	for i := 0; i < 2; i++ {
		if i > 0 {
			time.Sleep(punchPerSourceInterval + 200*time.Millisecond)
		}
		expiry := time.Now().Add(60 * time.Second).Unix()
		forged := mintPunchGrant(t, attackerPriv, attackerID, victimID, expiry)
		sendPunchRequest(t, attackerConn, attackerID, victimID, forged)
		expectNoPacket(t, attackerConn, 500*time.Millisecond)
		expectNoPacket(t, victimConn, 500*time.Millisecond)
	}

	// Step 2: forged Discover rebinding the victim's beacon-held key.
	sendDiscover(t, attackerConn, victimID, attackerPub)

	// The per-source punch rate limiter allows one punch per second.
	time.Sleep(punchPerSourceInterval + 200*time.Millisecond)

	// Steps 3+4: same forged grant, now verifiable against the rebound key.
	expiry := time.Now().Add(60 * time.Second).Unix()
	forged := mintPunchGrant(t, attackerPriv, attackerID, victimID, expiry)
	sendPunchRequest(t, attackerConn, attackerID, victimID, forged)

	buf := make([]byte, 64)
	attackerConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := attackerConn.Read(buf)
	if err != nil {
		t.Logf("no punch command reached the attacker — the token gate held (victim %v, attacker %v)", victimAddr, attackerAddr)
		return
	}
	if n >= 1 && buf[0] == protocol.BeaconMsgPunchCommand {
		t.Fatalf("ATTACK SUCCEEDED: require_punch_token=true yet the beacon coordinated a punch for an attacker holding no victim key")
	}
	t.Fatalf("unexpected reply type 0x%02x", buf[0])
}

// TestAttackReplay_DiscoverCannotRedirectToThirdParty is the bound on
// the finding, and the reason this is an interception primitive rather
// than a UDP reflector: handleDiscover upserts the *observed* source
// address, never an address chosen inside the payload. An attacker
// therefore cannot point a node ID at an unrelated victim host.
func TestAttackReplay_DiscoverCannotRedirectToThirdParty(t *testing.T) {
	t.Parallel()
	s, beaconAddr := startLocalBeacon(t, false)

	const nodeID = uint32(770006)

	// A third-party socket the attacker would love the beacon to
	// believe owns nodeID.
	thirdParty, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen third party: %v", err)
	}
	defer thirdParty.Close()
	thirdPartyAddr := thirdParty.LocalAddr().(*net.UDPAddr)

	attacker, err := net.DialUDP("udp", nil, beaconAddr)
	if err != nil {
		t.Fatalf("dial beacon: %v", err)
	}
	defer attacker.Close()
	attackerAddr := attacker.LocalAddr().(*net.UDPAddr)

	// Append a would-be address hint after the node ID; the wire format
	// has no such field, and the parser must ignore it entirely.
	msg := make([]byte, 5+6)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], nodeID)
	copy(msg[5:9], thirdPartyAddr.IP.To4())
	binary.BigEndian.PutUint16(msg[9:11], uint16(thirdPartyAddr.Port))
	if _, err := attacker.Write(msg); err != nil {
		t.Fatalf("send discover: %v", err)
	}

	if !waitUntil(2*time.Second, func() bool { return mappedAddr(t, s, nodeID) != nil }) {
		t.Fatal("node never registered")
	}
	got := mappedAddr(t, s, nodeID)
	if got.Port == thirdPartyAddr.Port {
		t.Fatalf("ATTACK SUCCEEDED: beacon accepted a payload-supplied endpoint %v — this is a reflector", got)
	}
	if got.Port != attackerAddr.Port {
		t.Fatalf("unexpected mapping: %v", got)
	}
}
