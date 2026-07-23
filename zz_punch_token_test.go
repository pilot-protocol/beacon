// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

func registerNodeWithPubKey(t *testing.T, beaconAddr *net.UDPAddr, nodeID uint32, pub ed25519.PublicKey) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, beaconAddr)
	if err != nil {
		t.Fatalf("dial beacon: %v", err)
	}

	msg := make([]byte, 1+4+len(pub))
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:5], nodeID)
	copy(msg[5:], pub)
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("send discover: %v", err)
	}

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read discover reply: %v", err)
	}
	if n < 1 || buf[0] != protocol.BeaconMsgDiscoverReply {
		t.Fatalf("unexpected reply type: 0x%02x", buf[0])
	}

	return conn
}

func mintPunchGrant(t *testing.T, priv ed25519.PrivateKey, requesterID, targetID uint32, expiry int64) []byte {
	t.Helper()
	trailer := make([]byte, punchGrantTrailerSize)
	binary.BigEndian.PutUint64(trailer[0:punchGrantExpirySize], uint64(expiry))
	preimage := fmt.Sprintf("punch-grant:%d:%d:%d", requesterID, targetID, expiry)
	sig := ed25519.Sign(priv, []byte(preimage))
	copy(trailer[punchGrantExpirySize:], sig)
	return trailer
}

func sendPunchRequest(t *testing.T, conn *net.UDPConn, requesterID, targetID uint32, trailer []byte) {
	t.Helper()
	msg := make([]byte, 1+8+len(trailer))
	msg[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(msg[1:5], requesterID)
	binary.BigEndian.PutUint32(msg[5:9], targetID)
	copy(msg[9:], trailer)
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("send punch request: %v", err)
	}
}

func expectPunchCommand(t *testing.T, conn *net.UDPConn, wantAddr *net.UDPAddr) {
	t.Helper()
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read punch command: %v", err)
	}
	if n < 2 || buf[0] != protocol.BeaconMsgPunchCommand {
		t.Fatalf("unexpected reply type: 0x%02x", buf[0])
	}
	ipLen := int(buf[1])
	if n < 2+ipLen+2 {
		t.Fatalf("short punch command: %d bytes", n)
	}
	gotIP := net.IP(buf[2 : 2+ipLen])
	gotPort := binary.BigEndian.Uint16(buf[2+ipLen : 2+ipLen+2])
	if !gotIP.Equal(wantAddr.IP) {
		t.Fatalf("punch command ip: got %v, want %v", gotIP, wantAddr.IP)
	}
	if int(gotPort) != wantAddr.Port {
		t.Fatalf("punch command port: got %d, want %d", gotPort, wantAddr.Port)
	}
}

func expectNoPacket(t *testing.T, conn *net.UDPConn, timeout time.Duration) {
	t.Helper()
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("expected no packet, got %d bytes (type 0x%02x)", n, buf[0])
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected read timeout, got %v", err)
	}
}

func TestPunchToken_FlagOff_BehavesAsToday(t *testing.T) {
	t.Parallel()
	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	beaconAddr := beaconUDPAddr(t, s)

	requesterID := uint32(9001)
	targetID := uint32(9002)

	conn1 := registerNode(t, beaconAddr, requesterID)
	defer conn1.Close()
	conn2 := registerNode(t, beaconAddr, targetID)
	defer conn2.Close()

	requesterAddr := conn1.LocalAddr().(*net.UDPAddr)
	targetAddr := conn2.LocalAddr().(*net.UDPAddr)

	sendPunchRequest(t, conn1, requesterID, targetID, nil)

	expectPunchCommand(t, conn1, targetAddr)
	expectPunchCommand(t, conn2, requesterAddr)
}

func TestPunchToken_FlagOn_NoToken_Dropped(t *testing.T) {
	t.Parallel()
	s := New()
	s.SetRequirePunchToken(true)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	beaconAddr := beaconUDPAddr(t, s)

	requesterID := uint32(9101)
	targetID := uint32(9102)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	conn1 := registerNode(t, beaconAddr, requesterID)
	defer conn1.Close()
	conn2 := registerNodeWithPubKey(t, beaconAddr, targetID, pub)
	defer conn2.Close()

	sendPunchRequest(t, conn1, requesterID, targetID, nil)

	expectNoPacket(t, conn1, 500*time.Millisecond)
	expectNoPacket(t, conn2, 500*time.Millisecond)
}

func TestPunchToken_FlagOn_ValidGrant_Succeeds(t *testing.T) {
	t.Parallel()
	s := New()
	s.SetRequirePunchToken(true)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	beaconAddr := beaconUDPAddr(t, s)

	requesterID := uint32(9201)
	targetID := uint32(9202)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	conn1 := registerNode(t, beaconAddr, requesterID)
	defer conn1.Close()
	conn2 := registerNodeWithPubKey(t, beaconAddr, targetID, pub)
	defer conn2.Close()

	requesterAddr := conn1.LocalAddr().(*net.UDPAddr)
	targetAddr := conn2.LocalAddr().(*net.UDPAddr)

	expiry := time.Now().Add(60 * time.Second).Unix()
	trailer := mintPunchGrant(t, priv, requesterID, targetID, expiry)

	sendPunchRequest(t, conn1, requesterID, targetID, trailer)

	expectPunchCommand(t, conn1, targetAddr)
	expectPunchCommand(t, conn2, requesterAddr)
}

func TestPunchToken_FlagOn_ExpiredGrant_Rejected(t *testing.T) {
	t.Parallel()
	s := New()
	s.SetRequirePunchToken(true)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	beaconAddr := beaconUDPAddr(t, s)

	requesterID := uint32(9301)
	targetID := uint32(9302)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	conn1 := registerNode(t, beaconAddr, requesterID)
	defer conn1.Close()
	conn2 := registerNodeWithPubKey(t, beaconAddr, targetID, pub)
	defer conn2.Close()

	expiry := time.Now().Add(-60 * time.Second).Unix()
	trailer := mintPunchGrant(t, priv, requesterID, targetID, expiry)

	sendPunchRequest(t, conn1, requesterID, targetID, trailer)

	expectNoPacket(t, conn1, 500*time.Millisecond)
	expectNoPacket(t, conn2, 500*time.Millisecond)
}

func TestPunchToken_FlagOn_WrongPairGrant_Rejected(t *testing.T) {
	t.Parallel()
	s := New()
	s.SetRequirePunchToken(true)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	beaconAddr := beaconUDPAddr(t, s)

	legitRequesterID := uint32(9401)
	attackerID := uint32(9402)
	targetID := uint32(9403)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	legitConn := registerNode(t, beaconAddr, legitRequesterID)
	defer legitConn.Close()
	attackerConn := registerNode(t, beaconAddr, attackerID)
	defer attackerConn.Close()
	targetConn := registerNodeWithPubKey(t, beaconAddr, targetID, pub)
	defer targetConn.Close()

	expiry := time.Now().Add(60 * time.Second).Unix()
	grantForLegitRequester := mintPunchGrant(t, priv, legitRequesterID, targetID, expiry)

	sendPunchRequest(t, attackerConn, attackerID, targetID, grantForLegitRequester)

	expectNoPacket(t, attackerConn, 500*time.Millisecond)
	expectNoPacket(t, targetConn, 500*time.Millisecond)
}

func TestPunchToken_NotFoundVsUnauthorized_Indistinguishable(t *testing.T) {
	t.Parallel()
	s := New()
	s.SetRequirePunchToken(true)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	beaconAddr := beaconUDPAddr(t, s)

	requesterID := uint32(9501)
	unregisteredTargetID := uint32(9502)
	registeredTargetID := uint32(9503)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	requesterConnA := registerNode(t, beaconAddr, requesterID)
	defer requesterConnA.Close()
	targetConn := registerNodeWithPubKey(t, beaconAddr, registeredTargetID, pub)
	defer targetConn.Close()

	sendPunchRequest(t, requesterConnA, requesterID, unregisteredTargetID, nil)
	expectNoPacket(t, requesterConnA, 500*time.Millisecond)

	sendPunchRequest(t, requesterConnA, requesterID, registeredTargetID, nil)
	expectNoPacket(t, requesterConnA, 500*time.Millisecond)
	expectNoPacket(t, targetConn, 500*time.Millisecond)
}
